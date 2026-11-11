# Fortnite HTTP MCP

Local HTTPS intercept / capture / edit / replay server for authorized API research.
Runs mitmproxy on `127.0.0.1:8080` and exposes an MCP endpoint on `127.0.0.1:26065/mcp`.

## Requirements

- Python 3.11+ (tested on 3.13)
- `pip install -r http_mcp/requirements.txt`

## Start

```
http_mcp\start.cmd
```

or

```
python -u http_mcp/server.py
```

Optional flags:

```
--port 26065 --proxy-port 8080 --scope-all --max-flows 5000 --max-body-bytes 1000000 --no-auth
```

On first start it creates:

- `%LOCALAPPDATA%\FortniteMCP\http\http_token.txt` - bearer token for the MCP endpoint
- `%LOCALAPPDATA%\FortniteMCP\http\mitmproxy\` - mitmproxy CA
- `%LOCALAPPDATA%\FortniteMCP\http\session-*.jsonl` - append-only capture log

The startup banner prints a ready-to-paste MCP client config:

```json
{
  "mcpServers": {
    "fortnite-http": {
      "type": "http",
      "url": "http://127.0.0.1:26065/mcp",
      "headers": { "Authorization": "Bearer <token from http_token.txt>" }
    }
  }
}
```

## Route traffic through the proxy

1. Install the CA (once): call tool `http_ca` with `{"action":"install","confirm":true}`,
   or run `certutil -user -addstore -f Root "%LOCALAPPDATA%\FortniteMCP\http\mitmproxy\mitmproxy-ca-cert.cer"`.
2. Point the client at the proxy:
   - WinINET-aware apps: tool `http_system_proxy` with `{"action":"on"}`, revert with `{"action":"off"}`.
   - The game (UE libcurl): set `HTTPS_PROXY=http://127.0.0.1:8080` and `HTTP_PROXY=http://127.0.0.1:8080`
     in the environment before launching, or add `[HTTP] ProxyAddress=127.0.0.1:8080` to the client
     `Engine.ini`. If no flows appear, the game is not honoring the proxy.
   - Anything else: use `--proxy http://127.0.0.1:8080` (curl) or the OS proxy settings.
3. Verify: load any Epic page, then call `http_flows`.

TLS note: if the client rejects the intercepted certificate, the endpoint is likely pinned.
The proxy log and `http_flows` will show a TLS/connection error rather than an HTTP flow.

## Tools

| Tool | Purpose |
| --- | --- |
| `http_status` | Proxy state, CA path/fingerprint, scope, capture counts, session file |
| `http_flows` | List flows (`host`, `path`, `method`, `status`, `text`, `since_s`, `limit`, `kind`) |
| `http_flow` | Full detail: headers, pretty JSON bodies, timing, TLS/ALPN/IP, WS frames |
| `http_send` | Craft and send a new request directly (text/JSON/base64 body) |
| `http_replay` | Resend a captured flow with method/url/header/body overrides |
| `http_curl` | Render a captured flow as a curl command |
| `http_har` | Export captured HTTP flows to HAR 1.2 |
| `http_ws` | List WebSocket connections or dump frames |
| `http_intercept` | Rules: hold or block matching requests/responses (`phase=request|response|both`) |
| `http_held` | List flows currently suspended |
| `http_held_release` | Continue (with edits), drop, or answer with a synthetic response |
| `http_tokens` | Extract Authorization/Cookie/token values, decode JWT claims |
| `http_diff` | Diff headers and bodies of two flows |
| `http_scope` | Host allowlist for capture (`*.epicgames.com` etc, `*` = everything) |
| `http_clear` | Clear in-memory captures (session file kept) |
| `http_ca` | CA info or install into CurrentUser Root |
| `http_system_proxy` | Read/enable/disable the WinINET proxy |

## Workflows

Find an API call:

```
http_status
http_flows {"host":"epicgames","path":"/account","limit":20}
http_flow {"id":"00012-ab12cd"}
http_tokens {"host":"epicgames"}
```

Edit a request in flight:

```
http_intercept {"action":"add","host":"epicgames","path":"/account","phase":"request","rule_action":"hold"}
# trigger the request from the client
http_held
http_held_release {"id":"00013-ff00aa","action":"continue","set_headers":{"X-Test":"1"}}
```

Fake a response:

```
http_held_release {"id":"00013-ff00aa","action":"respond","status":200,"body":{"ok":true},"headers":{"Content-Type":"application/json"}}
```

Replay with another account/session:

```
http_replay {"id":"00012-ab12cd","set_headers":{"Authorization":"Bearer <token>"},"label":"alt-account"}
```

## Scope and privacy

- Default scope records only Epic domains. Out-of-scope traffic is proxied but never stored.
- Captured headers include auth tokens and cookies; the session JSONL is plaintext under
  `%LOCALAPPDATA%`. Keep it private and delete it when done.
- Only test accounts and services you are authorized to test (Epic Games HackerOne program scope).

## Troubleshooting

- `401 unauthorized`: the MCP bearer token changed. Copy the current `http_token.txt`.
- Port in use: change `--port` / `--proxy-port`; `http_status` reports whether the proxy is up.
- CA not trusted: `curl --cacert <mitmproxy-ca-cert.pem>` works; Windows curl uses Schannel and may
  need the CA installed in the user Root store (`http_ca` install) or `-k` for a quick check.
- No flows at all: client ignores the proxy, or the host is out of scope (`http_scope`).
- TLS errors on one host only: likely certificate pinning on that endpoint.
