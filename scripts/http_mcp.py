#!/usr/bin/env python3
"""Call the local Fortnite HTTP MCP endpoint from a shell.

Usage:
  python scripts/http_mcp.py --list
  python scripts/http_mcp.py http_status
  python scripts/http_mcp.py http_flows '{"limit":10}'
  python scripts/http_mcp.py http_flow '{"id":"00001-ab12cd"}'
"""

import http.client
import json
import os
import pathlib
import sys

TOKEN_PATH = pathlib.Path(os.path.expandvars(r"%LOCALAPPDATA%\FortniteMCP\http\http_token.txt"))
HOST = "127.0.0.1"
PORT = 26065


def rpc(method, params=None, timeout=180):
    token = TOKEN_PATH.read_text(encoding="utf-8").strip()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    conn.request("POST", "/mcp", body,
                 {"Content-Type": "application/json", "Authorization": "Bearer " + token})
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, json.loads(data)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    if sys.argv[1] in ("--list", "-l"):
        status, reply = rpc("tools/list")
        for tool in reply["result"]["tools"]:
            print(tool["name"])
        return 0
    tool = sys.argv[1]
    arguments = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    status, reply = rpc("tools/call", {"name": tool, "arguments": arguments})
    if "error" in reply:
        print(json.dumps(reply, indent=2))
        return 2
    result = reply["result"]
    print(result["content"][0]["text"])
    return 3 if result.get("isError") else 0


if __name__ == "__main__":
    sys.exit(main())
