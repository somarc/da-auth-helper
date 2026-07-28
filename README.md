# da-auth-helper

Standalone IMS OAuth 2.0 implicit-flow authentication helper for [da.live](https://da.live) and the DA MCP server.

Designed to be used by any LLM agent, CLI tool, or Node.js application that needs a valid Adobe IMS access token without bundling a full framework.

## How it works

1. Checks `~/.aem/da-token.json` for a cached, non-expired token.
2. If none, starts a local HTTP server on port **9898**, opens the IMS login page in the user's default browser, waits for the OAuth callback, persists the token, and shuts down.
3. Returns the token string.

IMS issues tokens with a 24-hour lifetime.

## Run

Run directly without installing:

```bash
npx github:adobe-rnd/da-auth-helper token
```

## Programmatic API

```js
import { getValidToken, clearStoredToken } from 'da-auth-helper';

// Get a token (cached or via browser login)
const token = await getValidToken();

// Use it with the DA API or MCP server
const res = await fetch('https://admin.da.live/list/org/repo', {
  headers: { Authorization: `Bearer ${token}` },
});

// Force re-login on next call
await clearStoredToken();
```

### `getValidToken(opts?)`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `override` | `string` | — | Hard-coded token (CI / env var). Skips all caching and browser flow. |
| `log` | `(msg: string) => void` | `console.info` | Status messages (browser URL, success, etc.). |
| `timeoutMs` | `number` | `300000` | How long to wait for the browser login before rejecting (ms). |

Returns `Promise<string>` — a valid access token.

### `clearStoredToken()`

Removes `~/.aem/da-token.json`. The next call to `getValidToken()` will trigger a fresh browser login.

Returns `Promise<void>`.

## CLI

```bash
# Print token to stdout (login if needed)
da-auth-helper token

# Alias for token
da-auth-helper login

# Clear cached token
da-auth-helper logout
```

`login` is an alias for `token`. Both return the cached token while it is valid, so neither triggers a new login. To force one, clear the cache first:

```bash
da-auth-helper logout && da-auth-helper token
```

Token is printed to **stdout**; status messages go to **stderr**, so shell pipelines work cleanly:

```bash
TOKEN=$(da-auth-helper token)
curl -H "Authorization: Bearer $TOKEN" https://admin.da.live/list/org/repo
```

## Use with the DA MCP server

```js
import { getValidToken } from 'da-auth-helper';
import { DaMcpClient } from '@adobe/da-mcp'; // example MCP client

const token = await getValidToken({ log: (m) => process.stderr.write(m + '\n') });
const client = new DaMcpClient({ token });
```

Or pass the token as an environment variable and use the override:

```js
const token = await getValidToken({ override: process.env.DA_TOKEN });
```

## Token storage

Tokens are stored at `~/.aem/da-token.json`:

```json
{
  "access_token": "eyJ...",
  "expires_at": 1743000000000
}
```

The file is user-scoped (not project-scoped). A 60-second clock-skew buffer is applied on expiry checks.

## Requirements

- Node.js 18+
- A browser accessible from the machine running the script
- Network access to `ims-na1.adobelogin.com`

## License

Apache-2.0
