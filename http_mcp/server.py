#!/usr/bin/env python3
"""Fortnite HTTP MCP - MITM capture, edit and replay server for authorized API research.

Runs a local mitmproxy instance plus an MCP (JSON-RPC over HTTP) endpoint.
Only loopback listeners; bearer-token auth; default capture scope is Epic domains.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import ctypes
import datetime
import fnmatch
import http.client
import json
import os
import re
import secrets
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import OrderedDict
from difflib import unified_diff
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import mitmproxy.options
import mitmproxy.http
from mitmproxy.tools import dump

APP_NAME = "FortniteHTTPMCP"
VERSION = "1.0.0"
MCP_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")

BASE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FortniteMCP" / "http"
LOG_PATH = BASE_DIR / "http_mcp.log"
TOKEN_PATH = BASE_DIR / "http_token.txt"

DEFAULT_SCOPE = [
    "epicgames.com", "*.epicgames.com",
    "epicgames.dev", "*.epicgames.dev",
    "epicgames.net", "*.epicgames.net",
    "fortnite.com", "*.fortnite.com",
    "unrealengine.com", "*.unrealengine.com",
]

HOP_HEADERS = {"content-length", "connection", "transfer-encoding", "host", "proxy-connection"}


def now() -> float:
    return time.time()


def iso_time(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def log(message: str) -> None:
    line = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass


class ToolError(Exception):
    pass


def _as_text(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, (tuple, list)):
        return "-".join(_as_text(item) for item in value if item is not None)
    return str(value)


def header_list(headers) -> list[list[str]]:
    try:
        return [[str(k), str(v)] for k, v in headers.items(multi=True)]
    except Exception:
        try:
            return [[str(k), str(v)] for k, v in headers.items()]
        except Exception:
            return []


def headers_lower(headers: list[list[str]]) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in headers}


def get_header(headers: list[list[str]], name: str) -> str | None:
    name = name.lower()
    for key, value in headers:
        if str(key).lower() == name:
            return str(value)
    return None


def parse_cookies(headers: list[list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers:
        if str(key).lower() != "cookie":
            continue
        for part in str(value).split(";"):
            if "=" in part:
                name, cookie_value = part.split("=", 1)
                out[name.strip()] = cookie_value.strip()
    return out


def is_json_type(content_type: str | None, text: str | None = None) -> bool:
    ctype = (content_type or "").lower()
    if "json" in ctype:
        return True
    if text:
        stripped = text.lstrip()
        return stripped.startswith("{") or stripped.startswith("[")
    return False


def looks_textual(content_type: str | None, data: bytes) -> bool:
    ctype = (content_type or "").lower()
    if ctype.startswith("text/") or any(token in ctype for token in
                                        ("json", "xml", "javascript", "x-www-form-urlencoded",
                                         "graphql", "plain", "csv", "html")):
        return True
    sample = data[:4096]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    control = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return control / max(1, len(sample)) < 0.02


def render_body(data: bytes, content_type: str | None, total: int,
                truncated: bool, pretty: bool = True) -> dict:
    info: dict = {"bytes": total}
    if truncated:
        info["truncated"] = True
        info["captured_bytes"] = len(data)
    text = None
    if looks_textual(content_type, data):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
    if text is None:
        info["encoding"] = "base64"
        info["base64"] = base64.b64encode(data).decode("ascii")
        info["hex_preview"] = data[:64].hex()
        return info
    info["encoding"] = "utf8"
    if pretty and is_json_type(content_type, text):
        try:
            info["text"] = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
            info["json_parsed"] = True
            return info
        except (ValueError, TypeError):
            pass
    info["text"] = text
    return info


def grab_content(message, limit: int) -> tuple[bytes, int, bool]:
    try:
        data = message.content or b""
    except Exception:
        try:
            data = message.raw_content or b""
        except Exception:
            data = b""
    total = len(data)
    return data[:limit], total, total > limit


def body_arg_to_bytes(value) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, dict):
        if "base64" in value:
            return base64.b64decode(value["base64"])
        if "text" in value:
            return str(value["text"]).encode("utf-8")
        if "json" in value:
            return json.dumps(value["json"]).encode("utf-8")
        return json.dumps(value).encode("utf-8")
    if isinstance(value, (dict, list)):
        return json.dumps(value).encode("utf-8")
    if isinstance(value, str):
        return value.encode("utf-8")
    return str(value).encode("utf-8")


def normalize_headers_arg(value) -> list[list[str]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [[str(k), str(v)] for k, v in value.items()]
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict) and "name" in item:
                out.append([str(item["name"]), str(item.get("value", ""))])
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                out.append([str(item[0]), str(item[1])])
        return out
    raise ToolError("headers must be an object or a list of [name, value] pairs")


def merge_headers(base: list[list[str]], set_headers, add_headers, remove_headers) -> list[list[str]]:
    removed = {str(name).lower() for name in (remove_headers or [])}
    result = [[k, v] for k, v in base if k.lower() not in removed]
    for name, value in (normalize_headers_arg(set_headers)):
        result = [[k, v] for k, v in result if k.lower() != name.lower()]
        result.append([name, str(value)])
    result.extend(normalize_headers_arg(add_headers))
    return result


def to_mitm_headers(pairs) -> list[tuple[bytes, bytes]]:
    return [(str(k).encode("utf-8"), str(v).encode("utf-8")) for k, v in pairs]


def decode_jwt(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None
    info = {"claims": claims}
    expires = claims.get("exp")
    if isinstance(expires, (int, float)):
        info["expires_at"] = iso_time(float(expires))
        info["expires_in_s"] = int(expires - now())
    return info


def mask(value: str) -> str:
    if len(value) <= 20:
        return value[:4] + "..." + value[-4:]
    return value[:16] + "..." + value[-6:]


class Store:
    def __init__(self, max_flows: int, max_body: int, session_path: Path):
        self.max_flows = max_flows
        self.max_body = max_body
        self.session_path = session_path
        self.records: OrderedDict[str, dict] = OrderedDict()
        self.lock = threading.RLock()
        self.seq = 0
        self.tls_failures: OrderedDict[str, dict] = OrderedDict()
        self.persist_handle = open(session_path, "a", encoding="utf-8", buffering=1)
        self.persist_lock = threading.Lock()

    def _new_id(self) -> str:
        with self.lock:
            self.seq += 1
            return f"{self.seq:05d}-{uuid.uuid4().hex[:6]}"

    def _trim(self) -> None:
        while len(self.records) > self.max_flows:
            self.records.popitem(last=False)

    def _request_snapshot(self, req) -> dict:
        data, total, truncated = grab_content(req, self.max_body)
        ctype = req.headers.get("content-type", "")
        return {
            "method": req.method,
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "path": req.path,
            "url": req.url,
            "http_version": req.http_version,
            "headers": header_list(req.headers),
            "query": urllib.parse.parse_qsl(urllib.parse.urlsplit(req.url).query,
                                            keep_blank_values=True),
            "cookies": parse_cookies(header_list(req.headers)),
            "content_type": ctype,
            "body": render_body(data, ctype, total, truncated),
        }

    def start_http(self, flow) -> dict:
        record = {
            "id": self._new_id(),
            "kind": "http",
            "started_at": flow.timestamp_start or now(),
            "started_iso": iso_time(flow.timestamp_start or now()),
            "client": str(flow.client_conn.peername) if flow.client_conn else None,
            "request": self._request_snapshot(flow.request),
            "response": None,
            "error": None,
            "held": False,
        }
        with self.lock:
            self.records[record["id"]] = record
            self._trim()
        return record

    def refresh_request(self, flow) -> None:
        rec_id = flow.metadata.get("fmcp_id")
        if not rec_id:
            return
        snapshot = self._request_snapshot(flow.request)
        with self.lock:
            record = self.records.get(rec_id)
            if record is not None:
                record["request"] = snapshot

    def finish_http(self, flow) -> None:
        rec_id = flow.metadata.get("fmcp_id")
        if not rec_id:
            return
        resp = flow.response
        with self.lock:
            record = self.records.get(rec_id)
            if not record:
                return
            if resp is not None:
                data, total, truncated = grab_content(resp, self.max_body)
                ctype = resp.headers.get("content-type", "")
                record["response"] = {
                    "status": resp.status_code,
                    "reason": resp.reason,
                    "http_version": resp.http_version,
                    "headers": header_list(resp.headers),
                    "cookies": parse_cookies(header_list(resp.headers)),
                    "content_type": ctype,
                    "body": render_body(data, ctype, total, truncated),
                }
            start = flow.timestamp_start or record["started_at"]
            end = (resp.timestamp_end if resp and resp.timestamp_end else now())
            record["duration_ms"] = round((end - start) * 1000.0, 2)
            record["timing"] = {
                "request_start": round(((flow.request.timestamp_start or start) - start) * 1000.0, 2),
                "request_end": round(((flow.request.timestamp_end or start) - start) * 1000.0, 2),
                "response_start": round(((resp.timestamp_start or end) - start) * 1000.0, 2) if resp else None,
                "response_end": round(((resp.timestamp_end or end) - start) * 1000.0, 2) if resp else None,
            }
            conn = flow.server_conn
            record["server"] = {
                "ip": str(conn.peername[0]) if conn and conn.peername else None,
                "port": int(conn.peername[1]) if conn and conn.peername else None,
                "sni": _as_text(conn.sni) if conn else None,
                "alpn": _as_text(conn.alpn) if conn else None,
                "tls_version": _as_text(conn.tls_version) if conn else None,
                "cipher": _as_text(conn.cipher) if conn else None,
            }
            if flow.error:
                record["error"] = flow.error.msg
        self.persist(rec_id)

    def fail_http(self, flow) -> None:
        rec_id = flow.metadata.get("fmcp_id")
        if not rec_id:
            return
        with self.lock:
            record = self.records.get(rec_id)
            if record is None:
                return
            if flow.error:
                record["error"] = flow.error.msg
            record["duration_ms"] = round((now() - record["started_at"]) * 1000.0, 2)
        self.persist(rec_id)

    def start_ws(self, flow) -> None:
        rec_id = flow.metadata.get("fmcp_id")
        if not rec_id:
            return
        with self.lock:
            record = self.records.get(rec_id)
            if record is None:
                return
            record["kind"] = "ws"
            record["ws"] = {"messages": [], "message_count": 0, "truncated": False}
            resp = flow.response
            if resp is not None:
                ctype = resp.headers.get("content-type", "")
                data, total, truncated = grab_content(resp, self.max_body)
                record["response"] = {
                    "status": resp.status_code,
                    "reason": resp.reason,
                    "http_version": resp.http_version,
                    "headers": header_list(resp.headers),
                    "content_type": ctype,
                    "body": render_body(data, ctype, total, truncated),
                }

    def ws_message(self, flow) -> None:
        rec_id = flow.metadata.get("fmcp_id")
        if not rec_id:
            return
        try:
            message = flow.websocket.messages[-1]
        except (AttributeError, IndexError):
            return
        content = message.content
        if isinstance(content, str):
            data = content.encode("utf-8")
            opcode = "text"
        else:
            data = content or b""
            opcode = getattr(message.type, "name", str(message.type)).lower()
        truncated = len(data) > 65536
        entry = {
            "from_client": bool(message.from_client),
            "direction": "c2s" if message.from_client else "s2c",
            "opcode": opcode,
            "timestamp": iso_time(message.timestamp) if message.timestamp else None,
            "body": render_body(data[:65536], "text/plain" if opcode == "text" else None,
                                len(data), truncated),
        }
        with self.lock:
            record = self.records.get(rec_id)
            if record is None or "ws" not in record:
                return
            ws = record["ws"]
            ws["message_count"] += 1
            if len(ws["messages"]) < 2000:
                ws["messages"].append(entry)
            else:
                ws["truncated"] = True

    def end_ws(self, flow) -> None:
        rec_id = flow.metadata.get("fmcp_id")
        if not rec_id:
            return
        with self.lock:
            record = self.records.get(rec_id)
            if record is None:
                return
            record["duration_ms"] = round((now() - record["started_at"]) * 1000.0, 2)
            if flow.error:
                record["error"] = flow.error.msg
        self.persist(rec_id)

    def tls_failure(self, phase: str, conn, ctx) -> None:
        host = getattr(conn, "sni", None) or (ctx.server.address[0] if ctx and ctx.server.address else None)
        peer = getattr(conn, "peername", None)
        error = getattr(conn, "error", None)
        message = getattr(error, "msg", None) if error else None
        entry = {
            "time": iso_time(now()),
            "phase": phase,
            "host": str(host) if host else None,
            "peer": str(peer) if peer else None,
            "error": message,
        }
        with self.lock:
            self.tls_failures[entry["time"] + str(uuid.uuid4())[:4]] = entry
            while len(self.tls_failures) > 100:
                self.tls_failures.popitem(last=False)
        log(f"TLS failure ({phase}) host={entry['host']} error={message}")

    def tls_summary(self) -> list[dict]:
        with self.lock:
            return list(self.tls_failures.values())[-20:]

    def mark_held(self, rec_id: str, held: bool, rule_id: str | None) -> None:
        with self.lock:
            record = self.records.get(rec_id)
            if record is not None:
                record["held"] = held
                record["held_rule"] = rule_id
                record["held_since"] = now() if held else None

    def mark(self, rec_id: str, **values) -> None:
        with self.lock:
            record = self.records.get(rec_id)
            if record is not None:
                record.update(values)

    def add_replay(self, request: dict, response: dict | None, error: str | None,
                   duration_ms: float, label: str | None) -> dict:
        record = {
            "id": self._new_id(),
            "kind": "replay",
            "started_at": now(),
            "started_iso": iso_time(now()),
            "label": label,
            "request": request,
            "response": response,
            "error": error,
            "duration_ms": round(duration_ms, 2),
        }
        with self.lock:
            self.records[record["id"]] = record
            self._trim()
        self.persist(record["id"])
        return record

    def persist(self, rec_id: str) -> None:
        try:
            with self.lock:
                record = self.records.get(rec_id)
                if record is None:
                    return
                line = json.dumps(record, ensure_ascii=False)
            with self.persist_lock:
                self.persist_handle.write(line + "\n")
        except Exception as exc:
            log(f"persist failed: {exc}")

    def snapshot(self, rec_id: str) -> dict:
        with self.lock:
            record = self.records.get(rec_id)
            if record is None:
                raise ToolError(f"flow not found: {rec_id}")
            return json.loads(json.dumps(record))

    def summaries(self, args: dict) -> dict:
        host_re = args.get("host")
        path_re = args.get("path")
        method = (args.get("method") or "").upper()
        status_filter = str(args.get("status") or "")
        text = (args.get("text") or "").lower()
        kind = args.get("kind")
        since_s = args.get("since_s")
        limit = min(int(args.get("limit", 50)), 500)
        cutoff = now() - float(since_s) if since_s else None
        matched = []
        with self.lock:
            records = list(self.records.values())[::-1]
            for record in records:
                if kind and record.get("kind") != kind:
                    continue
                req = record.get("request") or {}
                url = req.get("url", "")
                if host_re and not re.search(host_re, req.get("host", ""), re.I):
                    continue
                if path_re and not re.search(path_re, req.get("path", ""), re.I):
                    continue
                if method and req.get("method", "").upper() != method:
                    continue
                if status_filter:
                    resp = record.get("response") or {}
                    status = resp.get("status")
                    if status is None:
                        continue
                    if re.fullmatch(r"[1-5]xx", status_filter, re.I):
                        if str(status)[0] != status_filter[0]:
                            continue
                    elif str(status) != status_filter:
                        continue
                if cutoff and record.get("started_at", 0) < cutoff:
                    continue
                if text:
                    blob = [url]
                    resp = record.get("response") or {}
                    req_body = (req.get("body") or {}).get("text")
                    res_body = (resp.get("body") or {}).get("text")
                    if req_body:
                        blob.append(req_body[:65536])
                    if res_body:
                        blob.append(res_body[:65536])
                    blob.append(json.dumps(req.get("headers") or []))
                    if text not in "\n".join(blob).lower():
                        continue
                resp = record.get("response") or {}
                summary = {
                    "id": record["id"],
                    "time": record.get("started_iso"),
                    "kind": record.get("kind"),
                    "method": req.get("method"),
                    "url": url,
                    "status": resp.get("status"),
                    "duration_ms": record.get("duration_ms"),
                    "req_bytes": (req.get("body") or {}).get("bytes", 0),
                    "res_bytes": (resp.get("body") or {}).get("bytes", 0),
                    "held": record.get("held", False),
                    "error": record.get("error"),
                }
                if record.get("kind") == "ws":
                    summary["ws_frames"] = (record.get("ws") or {}).get("message_count", 0)
                matched.append(summary)
        return {"matched": len(matched), "returned": min(limit, len(matched)),
                "flows": matched[:limit]}

    def clear(self) -> int:
        with self.lock:
            count = len(self.records)
            self.records.clear()
        return count

    def counts(self) -> dict:
        with self.lock:
            kinds: dict[str, int] = {}
            for record in self.records.values():
                kinds[record.get("kind", "http")] = kinds.get(record.get("kind", "http"), 0) + 1
            return {"total": len(self.records), "kinds": kinds}


class Scope:
    def __init__(self, patterns: list[str]):
        self.patterns = patterns
        self.lock = threading.RLock()

    def captures_all(self) -> bool:
        return "*" in self.patterns

    def captures(self, host: str) -> bool:
        host = (host or "").lower()
        with self.lock:
            if "*" in self.patterns:
                return True
            for pattern in self.patterns:
                if fnmatch.fnmatch(host, pattern.lower()):
                    return True
        return False

    def get(self) -> list[str]:
        with self.lock:
            return list(self.patterns)

    def set(self, patterns: list[str]) -> None:
        with self.lock:
            self.patterns = patterns or ["*"]


class Holder:
    def __init__(self, store: Store, hold_timeout: float = 600.0):
        self.store = store
        self.rules: list[dict] = []
        self.held: OrderedDict[str, dict] = OrderedDict()
        self.lock = threading.RLock()
        self.hold_timeout = hold_timeout

    def add_rule(self, rule: dict) -> dict:
        rule = dict(rule)
        rule["id"] = "r" + uuid.uuid4().hex[:8]
        rule.setdefault("phase", "request")
        rule.setdefault("action", "hold")
        with self.lock:
            self.rules.append(rule)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        with self.lock:
            before = len(self.rules)
            self.rules = [rule for rule in self.rules if rule["id"] != rule_id]
            return len(self.rules) != before

    def clear_rules(self) -> int:
        with self.lock:
            count = len(self.rules)
            self.rules = []
            return count

    def list_rules(self) -> list[dict]:
        with self.lock:
            return [dict(rule) for rule in self.rules]

    def match(self, flow, phase: str) -> dict | None:
        method = flow.request.method.upper()
        host = flow.request.host
        path = flow.request.path
        with self.lock:
            rules = list(self.rules)
        for rule in rules:
            if rule.get("phase") not in (phase, "both"):
                continue
            if rule.get("method") and rule["method"].upper() != method:
                continue
            if rule.get("host") and not re.search(rule["host"], host, re.I):
                continue
            if rule.get("path") and not re.search(rule["path"], path, re.I):
                continue
            return rule
        return None

    def count(self) -> int:
        with self.lock:
            return len(self.held)

    def list_held(self) -> list[dict]:
        out = []
        with self.lock:
            entries = list(self.held.values())
        for entry in entries:
            flow = entry["flow"]
            out.append({
                "id": entry["id"],
                "phase": entry["phase"],
                "rule": entry["rule"],
                "age_ms": round((now() - entry["created"]) * 1000.0, 1),
                "method": flow.request.method,
                "url": flow.request.url,
                "request_headers": [k for k, _ in header_list(flow.request.headers)],
            })
        return out

    async def hold(self, flow, rec_id: str, phase: str, rule: dict) -> None:
        entry = {
            "id": rec_id,
            "phase": phase,
            "rule": rule.get("id"),
            "flow": flow,
            "created": now(),
            "event": asyncio.Event(),
            "loop": asyncio.get_running_loop(),
            "action": "continue",
            "overrides": {},
            "response": None,
            "lock": threading.Lock(),
        }
        with self.lock:
            self.held[rec_id] = entry
        self.store.mark_held(rec_id, True, rule.get("id"))
        timeout = float(rule.get("timeout_s") or self.hold_timeout)
        try:
            await asyncio.wait_for(entry["event"].wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self.store.mark(rec_id, hold_timeout=True)
            log(f"hold timeout for {rec_id}")
        finally:
            with self.lock:
                self.held.pop(rec_id, None)
            self.store.mark_held(rec_id, False, None)

        action = entry["action"]
        overrides = entry["overrides"] or {}
        if action == "drop":
            flow.kill()
            return
        if action == "respond" and phase == "request":
            spec = entry["response"] or {}
            body = body_arg_to_bytes(spec.get("body"))
            headers = normalize_headers_arg(spec.get("headers"))
            flow.response = mitmproxy.http.Response.make(
                int(spec.get("status", 403)), body or b"", to_mitm_headers(headers))
            return
        if phase == "request":
            apply_request_overrides(flow.request, overrides)
            self.store.refresh_request(flow)
        elif flow.response is not None:
            apply_response_overrides(flow.response, overrides)

    def release(self, rec_id: str, action: str, overrides: dict, response: dict | None) -> dict:
        with self.lock:
            entry = self.held.get(rec_id)
        if entry is None:
            raise ToolError(f"flow is not held: {rec_id}")
        with entry["lock"]:
            entry["action"] = action
            entry["overrides"] = overrides or {}
            if response is not None:
                entry["response"] = response
        entry["loop"].call_soon_threadsafe(entry["event"].set)
        return {"id": rec_id, "action": action, "overrides": overrides or {}}


def apply_request_overrides(request, overrides: dict) -> None:
    if not overrides:
        return
    if overrides.get("method"):
        request.method = str(overrides["method"]).upper()
    if overrides.get("url"):
        request.url = str(overrides["url"])
    remove = overrides.get("remove_headers") or []
    for name in remove:
        try:
            del request.headers[str(name)]
        except KeyError:
            pass
    for name, value in normalize_headers_arg(overrides.get("set_headers")):
        request.headers[str(name)] = str(value)
    for name, value in normalize_headers_arg(overrides.get("add_headers")):
        request.headers.add(str(name), str(value))
    if "body" in overrides:
        request.content = body_arg_to_bytes(overrides["body"]) or b""


def apply_response_overrides(response, overrides: dict) -> None:
    if overrides.get("status"):
        response.status_code = int(overrides["status"])
    if overrides.get("reason"):
        response.reason = str(overrides["reason"])
    for name in overrides.get("remove_headers") or []:
        try:
            del response.headers[str(name)]
        except KeyError:
            pass
    for name, value in normalize_headers_arg(overrides.get("set_headers")):
        response.headers[str(name)] = str(value)
    for name, value in normalize_headers_arg(overrides.get("add_headers")):
        response.headers.add(str(name), str(value))
    if "body" in overrides:
        response.content = body_arg_to_bytes(overrides["body"]) or b""


class Recorder:
    def __init__(self, store: Store, holder: Holder, scope: Scope):
        self.store = store
        self.holder = holder
        self.scope = scope
        self.ready = False

    def running(self):
        self.ready = True
        log("mitmproxy addon active")

    def done(self):
        self.ready = False

    async def request(self, flow):
        if not self.scope.captures(flow.request.host):
            return
        record = self.store.start_http(flow)
        flow.metadata["fmcp_id"] = record["id"]
        rule = self.holder.match(flow, "request")
        if not rule:
            return
        if rule.get("action") == "block":
            body = body_arg_to_bytes(rule.get("body")) or b""
            flow.response = mitmproxy.http.Response.make(
                int(rule.get("status", 403)), body,
                to_mitm_headers(normalize_headers_arg(rule.get("headers"))))
            return
        if rule.get("action") == "hold":
            await self.holder.hold(flow, record["id"], "request", rule)

    async def response(self, flow):
        if not flow.metadata.get("fmcp_id"):
            return
        rule = self.holder.match(flow, "response")
        if rule and rule.get("action") == "hold":
            await self.holder.hold(flow, flow.metadata["fmcp_id"], "response", rule)
        self.store.finish_http(flow)

    def error(self, flow):
        if flow.metadata.get("fmcp_id"):
            self.store.fail_http(flow)

    def websocket_start(self, flow):
        if flow.metadata.get("fmcp_id"):
            self.store.start_ws(flow)

    def websocket_message(self, flow):
        if flow.metadata.get("fmcp_id"):
            self.store.ws_message(flow)

    def websocket_end(self, flow):
        if flow.metadata.get("fmcp_id"):
            self.store.end_ws(flow)

    def tls_failed_client(self, data):
        self.store.tls_failure("client", data.conn, data.context)

    def tls_failed_server(self, data):
        self.store.tls_failure("server", data.conn, data.context)


class HttpTransport:
    def __init__(self, max_body: int):
        self.max_body = max_body

    def send(self, url: str, method: str, headers: list[list[str]], body: bytes | None,
             timeout: float, insecure: bool, follow_redirects: bool,
             max_redirects: int = 10) -> dict:
        redirects = []
        current_url = url
        current_method = method.upper()
        current_body = body
        current_headers = list(headers)
        start_all = now()
        for _ in range(max_redirects + 1):
            parts = urllib.parse.urlsplit(current_url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ToolError(f"invalid url: {current_url}")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            target = parts.path or "/"
            if parts.query:
                target += "?" + parts.query
            context = ssl.create_default_context()
            if insecure:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            if parts.scheme == "https":
                conn = http.client.HTTPSConnection(parts.hostname, port,
                                                   timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)

            send_headers = [[k, v] for k, v in current_headers
                            if k.lower() not in ("content-length", "connection", "transfer-encoding")]
            if not any(k.lower() == "host" for k, _ in send_headers):
                send_headers.insert(0, ["Host", parts.netloc])
            has_length = any(k.lower() == "content-length" for k, _ in send_headers)
            if current_body is not None and not has_length:
                send_headers.append(["Content-Length", str(len(current_body))])
            if current_body is None and current_method in ("POST", "PUT", "PATCH") and not has_length:
                send_headers.append(["Content-Length", "0"])
            try:
                conn.putrequest(current_method, target, skip_host=True, skip_accept_encoding=True)
                for key, value in send_headers:
                    conn.putheader(key, value)
                conn.endheaders(current_body)
                hop_start = now()
                response = conn.getresponse()
                data = response.read(self.max_body + 1)
                truncated = len(data) > self.max_body
                data = data[:self.max_body]
                elapsed = (now() - hop_start) * 1000.0
                result = {
                    "status": response.status,
                    "reason": response.reason,
                    "http_version": "HTTP/1.1" if response.version == 11 else str(response.version),
                    "headers": [[str(k), str(v)] for k, v in response.getheaders()],
                    "body": render_body(data, response.getheader("content-type"),
                                        len(data), truncated),
                    "duration_ms": round(elapsed, 2),
                }
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                conn.close()
                return {"ok": False, "error": f"{type(exc).__name__}: {exc}",
                        "redirects": redirects,
                        "duration_ms": round((now() - start_all) * 1000.0, 2)}
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            location = response.getheader("location")
            if follow_redirects and result["status"] in (301, 302, 303, 307, 308) and location:
                next_url = urllib.parse.urljoin(current_url, location)
                redirects.append({"status": result["status"], "url": next_url})
                if result["status"] in (301, 302, 303) and current_method != "GET":
                    current_method = "GET"
                    current_body = None
                    current_headers = [[k, v] for k, v in current_headers
                                       if k.lower() not in ("content-type", "content-length")]
                current_headers = [[k, v] for k, v in current_headers if k.lower() != "host"]
                current_url = next_url
                continue
            response_payload = {"ok": True, "request": {
                "method": current_method,
                "url": current_url,
                "headers": send_headers,
                "body_bytes": len(current_body) if current_body is not None else 0,
            }, "response": result, "redirects": redirects,
                "duration_ms": round((now() - start_all) * 1000.0, 2)}
            return response_payload
        return {"ok": False, "error": "too many redirects", "redirects": redirects,
                "duration_ms": round((now() - start_all) * 1000.0, 2)}


class App:
    def __init__(self, store: Store, holder: Holder, scope: Scope, transport: HttpTransport,
                 proxy_host: str, proxy_port: int, ca_dir: Path, started_at: float,
                 master_ref: dict):
        self.store = store
        self.holder = holder
        self.scope = scope
        self.transport = transport
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.ca_dir = ca_dir
        self.started_at = started_at
        self.master_ref = master_ref
        self.tools = build_tools(self)

    def handle(self, message) -> dict | list | None:
        if isinstance(message, list):
            replies = []
            for item in message:
                reply = self.handle_one(item)
                if reply is not None:
                    replies.append(reply)
            return replies or None
        return self.handle_one(message)

    def handle_one(self, message) -> dict | None:
        if not isinstance(message, dict):
            return {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32600, "message": "invalid request"}}
        method = message.get("method")
        msg_id = message.get("id")
        if not isinstance(method, str):
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32600, "message": "missing method"}}
        if method.startswith("notifications/"):
            return None
        if msg_id is None:
            return None
        params = message.get("params") or {}
        try:
            if method == "initialize":
                requested = params.get("protocolVersion") if isinstance(params, dict) else None
                protocol = requested if requested in MCP_PROTOCOLS else "2025-06-18"
                return {"jsonrpc": "2.0", "id": msg_id, "result": {
                    "protocolVersion": protocol,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": APP_NAME, "version": VERSION},
                    "instructions": (
                        "HTTP capture/replay for authorized API research. The proxy captures Epic "
                        "domains by default. Install the mitmproxy CA and route the client through "
                        "the proxy. Use http_flows/http_flow to inspect, http_held/http_held_release "
                        "to edit traffic in flight, and http_replay/http_send to resend requests."),
                }}
            if method == "ping":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
            if method == "tools/list":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {
                    "tools": [{"name": t["name"], "description": t["description"],
                               "inputSchema": t["schema"]} for t in self.tools]}}
            if method == "resources/list":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}
            if method == "prompts/list":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}
            if method == "tools/call":
                name = params.get("name") if isinstance(params, dict) else None
                arguments = params.get("arguments") if isinstance(params, dict) else None
                tool = next((t for t in self.tools if t["name"] == name), None)
                if tool is None:
                    raise ToolError(f"unknown tool: {name}")
                try:
                    result = tool["func"](arguments or {})
                    text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
                    return {"jsonrpc": "2.0", "id": msg_id, "result": {
                        "content": [{"type": "text", "text": text}], "isError": False}}
                except ToolError as exc:
                    return {"jsonrpc": "2.0", "id": msg_id, "result": {
                        "content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}}
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"}}
        except Exception as exc:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32603, "message": f"{type(exc).__name__}: {exc}"}}


def tool_status(app: App):
    ca_cert = app.ca_dir / "mitmproxy-ca-cert.cer"
    ca_pem = app.ca_dir / "mitmproxy-ca-cert.pem"
    cert_path = ca_cert if ca_cert.exists() else ca_pem
    fingerprint = None
    if cert_path.exists():
        try:
            pem = cert_path.read_text(encoding="utf-8", errors="ignore")
            if "BEGIN CERTIFICATE" in pem:
                der = ssl.PEM_cert_to_DER_cert(pem)
                import hashlib
                fingerprint = hashlib.sha256(der).hexdigest()
        except Exception:
            pass
    master = app.master_ref.get("master")
    running = bool(master and app.master_ref.get("ready"))
    return {
        "proxy": {"host": app.proxy_host, "port": app.proxy_port, "running": running,
                  "mode": "regular"},
        "ca": {"path": str(cert_path) if cert_path.exists() else str(app.ca_dir / "mitmproxy-ca-cert.cer"),
               "exists": cert_path.exists(), "sha256": fingerprint,
               "install_hint": "call http_ca with action=install and confirm=true (CurrentUser Root)"},
        "scope": {"patterns": app.scope.get(), "capture_all": app.scope.captures_all()},
        "captured": app.store.counts(),
        "held": app.holder.count(),
        "intercept_rules": len(app.holder.list_rules()),
        "tls_failures": app.store.tls_summary(),
        "session_file": str(app.store.session_path),
        "uptime_s": round(now() - app.started_at, 1),
    }


def tool_flows(app: App, args: dict):
    return app.store.summaries(args or {})


def tool_flow(app: App, args: dict):
    rec_id = args.get("id")
    if not rec_id:
        raise ToolError("id is required")
    record = app.store.snapshot(str(rec_id))
    max_chars = int(args.get("max_body_chars", 200000))
    for part in ("request", "response"):
        body = (record.get(part) or {}).get("body")
        if body and body.get("encoding") == "utf8" and isinstance(body.get("text"), str):
            if len(body["text"]) > max_chars:
                body["text"] = body["text"][:max_chars]
                body["truncated_for_output"] = True
    if record.get("kind") == "ws" and record.get("ws"):
        for message in record["ws"]["messages"]:
            body = message.get("body") or {}
            if body.get("encoding") == "utf8" and isinstance(body.get("text"), str):
                if len(body["text"]) > max_chars:
                    body["text"] = body["text"][:max_chars]
                    body["truncated_for_output"] = True
    return record


def tool_send(app: App, args: dict):
    url = args.get("url")
    if not url:
        raise ToolError("url is required")
    method = str(args.get("method") or "GET").upper()
    headers = normalize_headers_arg(args.get("headers"))
    body = body_arg_to_bytes(args.get("body"))
    if body is not None and not any(k.lower() == "content-type" for k, _ in headers):
        if args.get("body") is not None and isinstance(args.get("body"), (dict, list)):
            headers.append(["Content-Type", "application/json"])
    timeout = float(args.get("timeout_ms", 20000)) / 1000.0
    result = app.transport.send(url, method, headers, body, timeout,
                                bool(args.get("insecure", False)),
                                bool(args.get("follow_redirects", True)))
    request_snapshot = {
        "method": method, "url": url, "headers": headers,
        "body": render_body(body or b"", get_header(headers, "content-type"),
                            len(body or b""), False),
    }
    record = app.store.add_replay(request_snapshot, result.get("response"),
                                  result.get("error"), result.get("duration_ms", 0),
                                  args.get("label"))
    result["replay_id"] = record["id"]
    return result


def tool_replay(app: App, args: dict):
    rec_id = args.get("id")
    if not rec_id:
        raise ToolError("id is required")
    record = app.store.snapshot(str(rec_id))
    if record.get("kind") == "ws":
        raise ToolError("cannot replay a websocket flow as HTTP; use http_ws to inspect it")
    request = record.get("request") or {}
    body_info = request.get("body") or {}
    if body_info.get("truncated") and not args.get("allow_truncated_body"):
        raise ToolError("captured body was truncated; pass allow_truncated_body=true to replay "
                        "the stored prefix")
    method = str(args.get("method") or request.get("method") or "GET").upper()
    url = str(args.get("url") or request.get("url") or "")
    headers = [[k, v] for k, v in (request.get("headers") or [])
               if str(k).lower() not in HOP_HEADERS]
    headers = merge_headers(headers, args.get("set_headers"), args.get("add_headers"),
                            args.get("remove_headers"))
    body = None
    if "body" in args:
        body = body_arg_to_bytes(args["body"])
    elif body_info.get("encoding") == "base64":
        body = base64.b64decode(body_info.get("base64") or "")
    elif body_info.get("encoding") == "utf8":
        body = (body_info.get("text") or "").encode("utf-8")
    if body is not None and not any(k.lower() == "content-type" for k, _ in headers):
        ctype = (request.get("body") or {}).get("content_type") or "application/octet-stream"
        headers.append(["Content-Type", ctype])
    timeout = float(args.get("timeout_ms", 20000)) / 1000.0
    result = app.transport.send(url, method, headers, body, timeout,
                                bool(args.get("insecure", False)),
                                bool(args.get("follow_redirects", True)))
    replay_request = {
        "method": method, "url": url, "headers": headers,
        "body": render_body(body or b"", get_header(headers, "content-type") or "",
                            len(body or b""), False),
    }
    new_record = app.store.add_replay(replay_request, result.get("response"),
                                      result.get("error"), result.get("duration_ms", 0),
                                      args.get("label"))
    result["replay_id"] = new_record["id"]
    result["source_flow"] = rec_id
    return result


def tool_curl(app: App, args: dict):
    rec_id = args.get("id")
    if not rec_id:
        raise ToolError("id is required")
    record = app.store.snapshot(str(rec_id))
    request = record.get("request") or {}
    parts = ["curl", "-X", request.get("method", "GET")]
    for key, value in request.get("headers") or []:
        if key.lower() in ("content-length", "host", "connection", "accept-encoding"):
            continue
        parts += ["-H", shlex.quote(f"{key}: {value}")]
    body = request.get("body") or {}
    if body.get("encoding") == "utf8" and body.get("text"):
        parts += ["--data-raw", shlex.quote(body["text"])]
    elif body.get("encoding") == "base64" and body.get("base64"):
        parts += ["--data-binary", shlex.quote(base64.b64decode(body["base64"]).decode("latin-1"))]
    parts.append(shlex.quote(request.get("url", "")))
    return {"flow": rec_id, "curl": " ".join(parts)}


def tool_har(app: App, args: dict):
    path = args.get("path")
    if not path:
        raise ToolError("path is required")
    include_bodies = bool(args.get("include_bodies", True))
    entries = []
    with app.store.lock:
        records = list(app.store.records.values())
    for record in records:
        if record.get("kind") not in ("http", "replay"):
            continue
        request = record.get("request") or {}
        response = record.get("response") or {}
        if not request.get("url"):
            continue
        entry = {
            "startedDateTime": record.get("started_iso") or iso_time(record.get("started_at")),
            "time": record.get("duration_ms", 0),
            "request": {
                "method": request.get("method"),
                "url": request.get("url"),
                "httpVersion": request.get("http_version") or "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in request.get("headers") or []],
                "queryString": [{"name": k, "value": v} for k, v in request.get("query") or []],
                "cookies": [],
                "headersSize": -1,
                "bodySize": (request.get("body") or {}).get("bytes", 0),
            },
            "response": {
                "status": response.get("status", 0),
                "statusText": response.get("reason", ""),
                "httpVersion": response.get("http_version") or "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in response.get("headers") or []],
                "cookies": [],
                "content": {"size": (response.get("body") or {}).get("bytes", 0),
                            "mimeType": response.get("content_type") or ""},
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": (response.get("body") or {}).get("bytes", 0),
            },
            "cache": {},
            "timings": {"send": 0, "wait": record.get("duration_ms", 0), "receive": 0},
        }
        if include_bodies:
            req_body = request.get("body") or {}
            if req_body.get("text") is not None:
                entry["request"]["postData"] = {"mimeType": request.get("content_type") or "",
                                                "text": req_body["text"]}
            res_body = response.get("body") or {}
            if res_body.get("text") is not None:
                entry["response"]["content"]["text"] = res_body["text"]
            elif res_body.get("base64"):
                entry["response"]["content"]["text"] = res_body["base64"]
                entry["response"]["content"]["encoding"] = "base64"
        entries.append(entry)
    har = {"log": {"version": "1.2",
                   "creator": {"name": APP_NAME, "version": VERSION},
                   "entries": entries}}
    Path(path).write_text(json.dumps(har, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"path": str(path), "entries": len(entries)}


def tool_ws(app: App, args: dict):
    rec_id = args.get("id")
    if not rec_id:
        results = []
        with app.store.lock:
            records = list(app.store.records.values())[::-1]
        for record in records:
            if record.get("kind") != "ws":
                continue
            results.append({"id": record["id"], "url": (record.get("request") or {}).get("url"),
                            "frames": (record.get("ws") or {}).get("message_count", 0),
                            "truncated": (record.get("ws") or {}).get("truncated", False)})
            if len(results) >= int(args.get("limit", 50)):
                break
        return {"websockets": results}
    record = app.store.snapshot(str(rec_id))
    if "ws" not in record:
        raise ToolError("flow is not a websocket")
    max_chars = int(args.get("max_body_chars", 100000))
    for message in record["ws"]["messages"]:
        body = message.get("body") or {}
        if body.get("encoding") == "utf8" and isinstance(body.get("text"), str) \
                and len(body["text"]) > max_chars:
            body["text"] = body["text"][:max_chars]
            body["truncated_for_output"] = True
    return record


def tool_intercept(app: App, args: dict):
    action = str(args.get("action") or "list")
    if action == "list":
        return {"rules": app.holder.list_rules()}
    if action == "add":
        rule = app.holder.add_rule({
            "host": args.get("host"),
            "path": args.get("path"),
            "method": args.get("method"),
            "phase": args.get("phase", "request"),
            "action": args.get("rule_action", "hold"),
            "status": args.get("status"),
            "body": args.get("body"),
            "headers": args.get("headers"),
            "timeout_s": args.get("timeout_s"),
        })
        return {"rule": rule}
    if action == "remove":
        rule_id = args.get("id")
        if not rule_id:
            raise ToolError("id is required")
        return {"removed": app.holder.remove_rule(str(rule_id))}
    if action == "clear":
        return {"removed": app.holder.clear_rules()}
    raise ToolError("action must be list, add, remove or clear")


def tool_held(app: App, args: dict):
    return {"held": app.holder.list_held()}


def tool_release(app: App, args: dict):
    rec_id = args.get("id")
    if not rec_id:
        raise ToolError("id is required")
    action = str(args.get("action") or "continue")
    if action not in ("continue", "drop", "respond"):
        raise ToolError("action must be continue, drop or respond")
    overrides = {}
    for key in ("method", "url", "status", "reason", "body", "set_headers",
                "add_headers", "remove_headers"):
        if key in args:
            overrides[key] = args[key]
    response = None
    if action == "respond":
        response = {"status": args.get("status", 403),
                    "body": args.get("body"),
                    "headers": args.get("headers")}
    return app.holder.release(str(rec_id), action, overrides, response)


def tool_tokens(app: App, args: dict):
    include_values = bool(args.get("include_values", False))
    limit = int(args.get("limit", 50))
    host_re = args.get("host")
    found = []
    jwt_re = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
    with app.store.lock:
        records = list(app.store.records.values())[::-1]
    for record in records:
        request = record.get("request") or {}
        if host_re and not re.search(host_re, request.get("host", ""), re.I):
            continue
        entries = []
        for key, value in request.get("headers") or []:
            lower = key.lower()
            if lower in ("authorization", "cookie", "x-epicgames-authorization"):
                entries.append((f"header:{key}", value))
        body_info = request.get("body") or {}
        if body_info.get("text"):
            try:
                parsed = json.loads(body_info["text"])
                if isinstance(parsed, dict):
                    for key in ("access_token", "refresh_token", "id_token", "token",
                                "session", "authorization"):
                        if isinstance(parsed.get(key), str):
                            entries.append((f"body:{key}", parsed[key]))
            except (ValueError, TypeError):
                pass
        for source, value in entries:
            item = {"flow": record["id"], "url": request.get("url"), "source": source,
                    "value": value if include_values else mask(value)}
            token_match = jwt_re.search(value)
            if token_match:
                jwt_info = decode_jwt(token_match.group(0))
                if jwt_info:
                    item["jwt"] = jwt_info
            found.append(item)
        if len(found) >= limit:
            break
    return {"tokens": found[:limit], "note": "values masked unless include_values=true"}


def tool_diff(app: App, args: dict):
    id_a = args.get("a")
    id_b = args.get("b")
    if not id_a or not id_b:
        raise ToolError("a and b flow ids are required")
    left = app.store.snapshot(str(id_a))
    right = app.store.snapshot(str(id_b))
    headers_a = headers_lower((left.get("request") or {}).get("headers") or [])
    headers_b = headers_lower((right.get("request") or {}).get("headers") or [])
    changed = []
    for key in sorted(set(headers_a) | set(headers_b)):
        if headers_a.get(key) != headers_b.get(key):
            changed.append({"header": key, "a": headers_a.get(key), "b": headers_b.get(key)})
    body_a = ((left.get("request") or {}).get("body") or {}).get("text") or ""
    body_b = ((right.get("request") or {}).get("body") or {}).get("text") or ""
    diff_lines = list(unified_diff(body_a.splitlines(), body_b.splitlines(),
                                   fromfile=str(id_a), tofile=str(id_b), lineterm=""))
    max_chars = int(args.get("max_chars", 20000))
    text = "\n".join(diff_lines)
    truncated = len(text) > max_chars
    return {"a": id_a, "b": id_b,
            "request": {"a": (left.get("request") or {}).get("method", "") + " "
                             + (left.get("request") or {}).get("url", ""),
                        "b": (right.get("request") or {}).get("method", "") + " "
                             + (right.get("request") or {}).get("url", "")},
            "header_changes": changed,
            "body_diff": text[:max_chars], "body_diff_truncated": truncated}


def tool_scope(app: App, args: dict):
    action = str(args.get("action") or "get")
    if action == "get":
        return {"patterns": app.scope.get(), "capture_all": app.scope.captures_all()}
    if action == "set":
        patterns = args.get("patterns")
        if patterns is None:
            raise ToolError("patterns is required for action=set")
        if isinstance(patterns, str):
            patterns = [patterns]
        app.scope.set([str(p) for p in patterns])
        return {"patterns": app.scope.get(), "capture_all": app.scope.captures_all()}
    raise ToolError("action must be get or set")


def tool_clear(app: App, args: dict):
    if not args.get("confirm"):
        raise ToolError("pass confirm=true to clear captured flows")
    return {"cleared": app.store.clear()}


def tool_ca(app: App, args: dict):
    action = str(args.get("action") or "info")
    cert = app.ca_dir / "mitmproxy-ca-cert.cer"
    if not cert.exists():
        cert = app.ca_dir / "mitmproxy-ca-cert.pem"
    info = {"path": str(cert), "exists": cert.exists()}
    if cert.exists():
        try:
            pem = cert.read_text(encoding="utf-8", errors="ignore")
            if "BEGIN CERTIFICATE" in pem:
                import hashlib
                info["sha256"] = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        except Exception as exc:
            info["error"] = str(exc)
    if action == "info":
        return info
    if action == "install":
        if not args.get("confirm"):
            raise ToolError("pass confirm=true to add the CA to the CurrentUser Root store")
        if not cert.exists():
            raise ToolError("CA certificate not generated yet; start a TLS capture first")
        result = subprocess.run(["certutil", "-user", "-addstore", "-f", "Root", str(cert)],
                                capture_output=True, text=True, timeout=30)
        info["install"] = {"exit_code": result.returncode,
                           "stdout": result.stdout.strip(),
                           "stderr": result.stderr.strip()}
        return info
    raise ToolError("action must be info or install")


def tool_system_proxy(app: App, args: dict):
    import winreg
    action = str(args.get("action") or "get")
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                        winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        if action == "get":
            try:
                enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
            except FileNotFoundError:
                enabled = 0
            try:
                server = winreg.QueryValueEx(key, "ProxyServer")[0]
            except FileNotFoundError:
                server = ""
            return {"proxy_enable": int(enabled), "proxy_server": server,
                    "note": "WinINET/WinHTTP-aware apps only; WinHTTP may need netsh (admin)"}
        if action in ("on", "off"):
            value = 1 if action == "on" else 0
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, value)
            if action == "on":
                server = args.get("server") or f"127.0.0.1:{app.proxy_port}"
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            internet_set_option = ctypes.windll.wininet.InternetSetOptionW
            internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
            return {"proxy_enable": value, "changed": True}
        raise ToolError("action must be get, on or off")


def build_tools(app: App) -> list[dict]:
    return [
        {"name": "http_status", "description": "Proxy, CA, scope, capture counts and session file.",
         "schema": {"type": "object", "properties": {}, "additionalProperties": False},
         "func": lambda args: tool_status(app)},
        {"name": "http_flows",
         "description": "List captured HTTP/WebSocket/replay flows, newest first. Filters are regex; "
                        "status accepts 200 or 4xx; text searches URL, headers and captured bodies.",
         "schema": {"type": "object", "properties": {
             "host": {"type": "string"}, "path": {"type": "string"},
             "method": {"type": "string"}, "status": {"type": "string"},
             "text": {"type": "string"}, "kind": {"type": "string",
                                                 "enum": ["http", "ws", "replay"]},
             "since_s": {"type": "number"}, "limit": {"type": "integer", "minimum": 1,
                                                      "maximum": 500}},
             "additionalProperties": False},
         "func": lambda args: tool_flows(app, args)},
        {"name": "http_flow",
         "description": "Full detail for one flow: headers, bodies (JSON pretty-printed, binary as "
                        "base64+hex), timing, TLS/ALPN/server info, WebSocket frames.",
         "schema": {"type": "object", "properties": {
             "id": {"type": "string"},
             "max_body_chars": {"type": "integer", "minimum": 1000}},
             "required": ["id"], "additionalProperties": False},
         "func": lambda args: tool_flow(app, args)},
        {"name": "http_send",
         "description": "Send a new HTTP request directly (not through the game) and record it. "
                        "Body accepts text, JSON value, or {base64}. Optional label for the session log.",
         "schema": {"type": "object", "properties": {
             "url": {"type": "string"}, "method": {"type": "string"},
             "headers": {"type": ["object", "array"]},
             "body": {}, "timeout_ms": {"type": "integer"},
             "follow_redirects": {"type": "boolean"}, "insecure": {"type": "boolean"},
             "label": {"type": "string"}},
             "required": ["url"], "additionalProperties": False},
         "func": lambda args: tool_send(app, args)},
        {"name": "http_replay",
         "description": "Replay a captured flow with overrides (method/url/headers/body). "
                        "Auth and cookies are copied from the captured request.",
         "schema": {"type": "object", "properties": {
             "id": {"type": "string"}, "method": {"type": "string"}, "url": {"type": "string"},
             "set_headers": {"type": ["object", "array"]},
             "add_headers": {"type": ["object", "array"]},
             "remove_headers": {"type": "array", "items": {"type": "string"}},
             "body": {}, "timeout_ms": {"type": "integer"},
             "follow_redirects": {"type": "boolean"}, "insecure": {"type": "boolean"},
             "allow_truncated_body": {"type": "boolean"}, "label": {"type": "string"}},
             "required": ["id"], "additionalProperties": False},
         "func": lambda args: tool_replay(app, args)},
        {"name": "http_curl",
         "description": "Render a captured flow as a ready-to-run curl command.",
         "schema": {"type": "object", "properties": {"id": {"type": "string"}},
                    "required": ["id"], "additionalProperties": False},
         "func": lambda args: tool_curl(app, args)},
        {"name": "http_har",
         "description": "Export captured HTTP flows to a HAR 1.2 file.",
         "schema": {"type": "object", "properties": {
             "path": {"type": "string"},
             "include_bodies": {"type": "boolean"}},
             "required": ["path"], "additionalProperties": False},
         "func": lambda args: tool_har(app, args)},
        {"name": "http_ws",
         "description": "List WebSocket connections or dump frames for one flow.",
         "schema": {"type": "object", "properties": {
             "id": {"type": "string"}, "limit": {"type": "integer"},
             "max_body_chars": {"type": "integer"}},
             "additionalProperties": False},
         "func": lambda args: tool_ws(app, args)},
        {"name": "http_intercept",
         "description": "Manage intercept rules. add requires host/path regex. rule_action=hold "
                        "suspends matching traffic until http_held_release; rule_action=block returns "
                        "a synthetic response. phase=request|response|both.",
         "schema": {"type": "object", "properties": {
             "action": {"type": "string", "enum": ["list", "add", "remove", "clear"]},
             "id": {"type": "string"}, "host": {"type": "string"}, "path": {"type": "string"},
             "method": {"type": "string"},
             "phase": {"type": "string", "enum": ["request", "response", "both"]},
             "rule_action": {"type": "string", "enum": ["hold", "block"]},
             "status": {"type": "integer"}, "body": {}, "headers": {"type": ["object", "array"]},
             "timeout_s": {"type": "number"}},
             "additionalProperties": False},
         "func": lambda args: tool_intercept(app, args)},
        {"name": "http_held",
         "description": "List flows currently suspended by a hold rule.",
         "schema": {"type": "object", "properties": {}, "additionalProperties": False},
         "func": lambda args: tool_held(app, args)},
        {"name": "http_held_release",
         "description": "Release a held flow: continue (optionally with overrides), drop the "
                        "connection, or respond with a synthetic response.",
         "schema": {"type": "object", "properties": {
             "id": {"type": "string"},
             "action": {"type": "string", "enum": ["continue", "drop", "respond"]},
             "method": {"type": "string"}, "url": {"type": "string"},
             "status": {"type": "integer"}, "reason": {"type": "string"},
             "body": {}, "set_headers": {"type": ["object", "array"]},
             "add_headers": {"type": ["object", "array"]},
             "remove_headers": {"type": "array", "items": {"type": "string"}},
             "headers": {"type": ["object", "array"]}},
             "required": ["id"], "additionalProperties": False},
         "func": lambda args: tool_release(app, args)},
        {"name": "http_tokens",
         "description": "Extract Authorization/Cookie/token values from captured requests and decode "
                        "JWT claims (expiry, audience, scopes). Values masked by default.",
         "schema": {"type": "object", "properties": {
             "limit": {"type": "integer", "minimum": 1},
             "include_values": {"type": "boolean"}, "host": {"type": "string"}},
             "additionalProperties": False},
         "func": lambda args: tool_tokens(app, args)},
        {"name": "http_diff",
         "description": "Diff request headers and bodies of two flows.",
         "schema": {"type": "object", "properties": {
             "a": {"type": "string"}, "b": {"type": "string"},
             "max_chars": {"type": "integer"}},
             "required": ["a", "b"], "additionalProperties": False},
         "func": lambda args: tool_diff(app, args)},
        {"name": "http_scope",
         "description": "Get or set host capture scope (fnmatch patterns, '*' captures everything). "
                        "Out-of-scope traffic is proxied but never recorded.",
         "schema": {"type": "object", "properties": {
             "action": {"type": "string", "enum": ["get", "set"]},
             "patterns": {"type": ["array", "string"]}},
             "additionalProperties": False},
         "func": lambda args: tool_scope(app, args)},
        {"name": "http_clear",
         "description": "Clear captured flows from memory (session file is kept).",
         "schema": {"type": "object", "properties": {"confirm": {"type": "boolean"}},
                    "additionalProperties": False},
         "func": lambda args: tool_clear(app, args)},
        {"name": "http_ca",
         "description": "Show the mitmproxy CA path/fingerprint, or install it into the CurrentUser "
                        "Root store (action=install, confirm=true).",
         "schema": {"type": "object", "properties": {
             "action": {"type": "string", "enum": ["info", "install"]},
             "confirm": {"type": "boolean"}},
             "additionalProperties": False},
         "func": lambda args: tool_ca(app, args)},
        {"name": "http_system_proxy",
         "description": "Read, enable or disable the WinINET proxy (HKCU) pointing at this proxy. "
                        "WinHTTP services may still need netsh as admin.",
         "schema": {"type": "object", "properties": {
             "action": {"type": "string", "enum": ["get", "on", "off"]},
             "server": {"type": "string"}},
             "additionalProperties": False},
         "func": lambda args: tool_system_proxy(app, args)},
    ]


class McpHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"{APP_NAME}/{VERSION}"
    app: App = None
    token: str = ""

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, payload: bytes | None, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload) if payload else 0))
        self.send_header("Mcp-Session-Id", self.server.session_id)
        self.send_header("MCP-Protocol-Version", "2025-06-18")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _authorized(self) -> bool:
        if not self.token:
            return True
        values = []
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            values.append(header[7:].strip())
        values.append(self.headers.get("X-MCP-Token", "").strip())
        return any(secrets.compare_digest(v, self.token) for v in values if v)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._send(405, b'{"error":"use POST /mcp"}')

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != "/mcp":
            self._send(404, b'{"error":"not found"}')
            return
        if not self._authorized():
            self._send(401, b'{"error":"unauthorized"}')
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 16 * 1024 * 1024:
            self._send(400, b'{"error":"invalid content length"}')
            return
        try:
            message = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._send(400, b'{"error":"invalid json"}')
            return
        reply = self.app.handle(message)
        if reply is None:
            self._send(202, None)
            return
        body = json.dumps(reply, ensure_ascii=False).encode("utf-8")
        self._send(200, body)


def ensure_dirs() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "mitmproxy").mkdir(parents=True, exist_ok=True)


def read_or_create_token(path: Path, disabled: bool) -> str:
    if disabled:
        return ""
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_urlsafe(32)
    path.write_text(token + "\n", encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=26065)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--scope-all", action="store_true")
    parser.add_argument("--max-flows", type=int, default=5000)
    parser.add_argument("--max-body-bytes", type=int, default=1_000_000)
    parser.add_argument("--no-auth", action="store_true")
    parser.add_argument("--hold-timeout", type=float, default=600.0)
    args = parser.parse_args()

    ensure_dirs()
    token = read_or_create_token(TOKEN_PATH, args.no_auth)
    session_path = BASE_DIR / f"session-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl"

    store = Store(args.max_flows, args.max_body_bytes, session_path)
    scope = Scope(["*"] if args.scope_all else list(DEFAULT_SCOPE))
    holder = Holder(store, args.hold_timeout)
    transport = HttpTransport(args.max_body_bytes)

    opts = mitmproxy.options.Options(
        listen_host=args.proxy_host,
        listen_port=args.proxy_port,
        http2=True,
        confdir=str(BASE_DIR / "mitmproxy"),
    )
    loop = asyncio.new_event_loop()
    master = dump.DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
    recorder = Recorder(store, holder, scope)
    master.addons.add(recorder)
    master_ref = {"master": master, "ready": False}

    def run_proxy():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(master.run())
        except Exception as exc:
            log(f"mitmproxy stopped: {exc}")

    proxy_thread = threading.Thread(target=run_proxy, name="mitmproxy", daemon=True)
    proxy_thread.start()

    deadline = time.time() + 10
    proxy_up = False
    while time.time() < deadline:
        try:
            with socket.create_connection((args.proxy_host, args.proxy_port), timeout=0.5):
                proxy_up = True
                break
        except OSError:
            time.sleep(0.1)
    master_ref["ready"] = proxy_up
    if not proxy_up:
        log(f"proxy did not start on {args.proxy_host}:{args.proxy_port}")

    app = App(store, holder, scope, transport, args.proxy_host, args.proxy_port,
              BASE_DIR / "mitmproxy", time.time(), master_ref)

    server = ThreadingHTTPServer((args.host, args.port), McpHttpHandler)
    server.daemon_threads = True
    server.session_id = uuid.uuid4().hex
    McpHttpHandler.app = app
    McpHttpHandler.token = token
    server_thread = threading.Thread(target=server.serve_forever, name="mcp-http", daemon=True)
    server_thread.start()

    log(f"{APP_NAME} {VERSION} started")
    log(f"proxy: {args.proxy_host}:{args.proxy_port}  mcp: http://{args.host}:{args.port}/mcp")
    log(f"token file: {TOKEN_PATH}")
    log(f"session log: {session_path}")
    config = {"mcpServers": {"fortnite-http": {
        "type": "http", "url": f"http://{args.host}:{args.port}/mcp",
        "headers": {"Authorization": f"Bearer {token}"} if token else {}}}}
    print("MCP client config:\n" + json.dumps(config, indent=2), flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("shutting down")
    finally:
        try:
            loop.call_soon_threadsafe(master.should_exit.set)
        except Exception:
            pass
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
