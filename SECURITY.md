# Security policy

FortniteMCP is a local research tool for offline/private builds you own. It is not
affiliated with Epic Games and is not intended for use on live services.

## Intended use

- Offline or private test builds that you own, with anti-cheat disabled.
- Your own accounts and your own private sessions.
- Local, loopback-only MCP access with the generated bearer token.

## Prohibited use

- Public matches, online services, or other players.
- Anti-cheat bypass, hardware-ID spoofing, or hiding the tool from a protected process.
- Injecting into processes on other machines or processes you do not own.
- Denial-of-service testing against services you do not control.
- Capturing, replaying, or modifying another person's sessions or credentials.

The HTTP sidecar stores captured headers, cookies, and tokens in plaintext under
`%LOCALAPPDATA%\FortniteMCP\http\`. Treat that directory as sensitive and delete it when
you are done.

## Reporting a vulnerability

If you find a security issue in FortniteMCP itself (for example, an unauthenticated path
into the MCP server, a memory-safety bug, or a token leak), open a private GitHub security
advisory on this repository. Please do not include game memory dumps, account tokens, or
third-party personal data in the report.
