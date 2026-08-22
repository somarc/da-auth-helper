# da-auth-helper

Standalone Adobe IMS OAuth 2.0 implicit-flow authentication helper for [da.live](https://da.live) and DA tooling.

The package supports two deliberately different ownership models:

- `getValidToken()` preserves the original convenience behavior: return a valid default cached token or run a browser flow and atomically replace that cache.
- `acquireToken()` always performs a browser flow and returns an in-memory candidate without reading, removing, or writing the default cache. This is the integration surface for callers that own credential profiles and final persistence.

## Requirements

- Node.js 18 or newer
- A browser reachable from the machine running the helper, or a caller that handles the emitted authorization URL
- Network access to `ims-na1.adobelogin.com`
- Callback port `9898` available on localhost

## Install or run

Run directly from the repository:

```bash
npm ci
node src/cli.js token
```

Or run the GitHub package without installing it globally:

```bash
npx github:adobe-rnd/da-auth-helper token
```

Production integrations should pin a reviewed release or immutable commit rather than execute an unversioned branch head.

## Programmatic API

### Cached compatibility path

```js
import { getValidToken } from 'da-auth-helper';

const token = await getValidToken();
```

`getValidToken()` checks `~/.aem/da-token.json`, applies a 60-second expiry buffer, and starts the browser flow only when the cache is absent or expired. Existing callers still receive `Promise<string>`.

To explicitly require a new IMS authentication round trip:

```js
const token = await getValidToken({ reauthenticate: true });
```

`reauthenticate: true` bypasses the cache and adds `prompt=login` to the IMS request. It does **not** select or prove an Adobe account, IMS organization, DA organization, or repository authorization.

### Caller-owned acquisition path

```js
import { acquireToken } from 'da-auth-helper';

const controller = new AbortController();
const result = await acquireToken({
  reauthenticate: true,
  openBrowser: false,
  timeoutMs: 300_000,
  signal: controller.signal,
  onEvent(event) {
    if (event.event === 'authorization_url') {
      // Route event.url into a caller-owned browser.
    }
  },
});

// result.token is secret. The caller alone decides whether and where to store it.
```

`acquireToken()`:

- never reads, removes, or writes `~/.aem/da-token.json`;
- binds the callback listener before emitting the authorization URL;
- can suppress operating-system browser launch;
- supports deterministic timeout and `AbortSignal` cancellation;
- returns a freshly browser-acquired candidate and normalized expiry metadata.

Result shape:

```js
{
  token,                       // secret string
  expiresAt,                   // Unix epoch milliseconds or null
  expirySource,                // "jwt-exp", "ims-expires-in", or null
  tokenAcquired: true,
  persisted: false,
  reauthenticationRequested,  // boolean
}
```

### Options

| Option | Type | Default | Meaning |
|---|---|---:|---|
| `override` | `string` | — | `getValidToken()` only: return an explicit caller token without cache or browser activity. |
| `log` | `(message: string) => void` | `console.info` | `getValidToken()` human-readable status sink. It never receives the token. |
| `reauthenticate` | `boolean` | `false` | Bypass the helper cache where applicable and add IMS `prompt=login`. |
| `openBrowser` | `boolean` | `true` | Launch the operating-system browser. Set false for caller-owned browser handoff. |
| `timeoutMs` | `number` | `300000` | Positive integer attempt deadline, up to 30 minutes. |
| `signal` | `AbortSignal` | — | Cancels the callback listener and active attempt. |
| `onEvent` | `(event) => void \| Promise<void>` | — | Receives versioned, token-free lifecycle events. |

### Token-free event contract

Every event has `schema: "da-auth-helper.event.v1"`. Current event names are:

- `authorization_url` — exact allowlistable IMS URL, redirect URI, callback port, deadline, and reauthentication intent;
- `waiting` — periodic remaining-time liveness for long attempts;
- `callback_rejected` — a token-free code for an ignored malformed or state-mismatched callback;
- `completed` — acquisition/persistence and expiry metadata, never the token.

The callback is awaited. If the event sink fails, the helper closes the listener and rejects with `OUTPUT_FAILED` rather than continuing an unobservable attempt.

Programmatic failures are `AuthError` instances with stable codes such as:

- `CALLBACK_PORT_IN_USE`
- `AUTH_TIMEOUT`
- `AUTH_CANCELLED`
- `BROWSER_OPEN_FAILED`
- `CALLBACK_INVALID`
- `OAUTH_ACCESS_DENIED`
- `STORE_FAILED`
- `OUTPUT_FAILED`
- `INVALID_ARGUMENT`

Nested platform/provider errors are retained only as an in-memory `cause`; stable public messages do not interpolate them.

### Clearing the default cache

```js
import { clearStoredToken } from 'da-auth-helper';

await clearStoredToken();
```

## CLI

```bash
# Return a cached token or acquire and persist one.
da-auth-helper token

# Alias for token; it does not force a new login by itself.
da-auth-helper login

# Explicitly bypass cache and require a fresh IMS login.
da-auth-helper token --reauthenticate

# Acquire a caller-owned candidate without touching the default cache.
da-auth-helper acquire --reauthenticate

# Let another application open the authorization URL.
da-auth-helper acquire --reauthenticate --no-open --events=ndjson

# Clear the default cache.
da-auth-helper logout
```

Supported authentication flags:

```text
--reauthenticate
--no-open
--timeout-ms <positive integer>
--events=ndjson
```

Unknown flags fail closed.

### Output channels

The raw token is the **only stdout value**. Human status or versioned NDJSON events use stderr. A caller handling secrets must capture stdout privately and must not merge it into logs, chat, MCP results, or the event stream.

Example token-free stderr records:

```json
{"schema":"da-auth-helper.event.v1","event":"authorization_url","url":"https://ims-na1.adobelogin.com/ims/authorize/v2?...","callbackPort":9898,"deadlineAt":1780000000000,"reauthenticationRequested":true}
{"schema":"da-auth-helper.event.v1","event":"completed","tokenAcquired":true,"persisted":false,"expiresAt":1780000000000,"expirySource":"jwt-exp","reauthenticationRequested":true}
```

CLI failures in NDJSON mode add a token-free `error` record with `code`, `retryable`, and a stable message.

## Callback and credential security

Each browser attempt:

- generates and validates a 128-bit OAuth state nonce;
- binds localhost port `9898` before exposing or opening the URL;
- sends the fragment payload to localhost in a size-bounded POST body, not a request URL;
- uses no-store, no-referrer, nosniff, and restrictive CSP response headers;
- clears the browser fragment before the local handoff;
- reports browser completion only after the helper accepts the callback response;
- cleans up its timer, abort listener, callback server, and sockets on every terminal path.

The fixed callback port is the global attempt mutex. A concurrent attempt fails quickly with `CALLBACK_PORT_IN_USE`; it never joins or reuses another process's login.

Default cached credentials are stored at `~/.aem/da-token.json`. The helper validates that the directory and file are current-user-owned real filesystem objects, repairs their modes to `0700` and `0600`, rejects symlinks and multiply linked files, and replaces credentials through an exclusive same-directory temporary file plus atomic rename. The prior credential remains intact until replacement succeeds.

IMS commonly issues 24-hour tokens. Expiry is normalized to Unix epoch milliseconds from a bounded JWT `exp` claim when available, otherwise from a bounded IMS `expires_in` value. Callers that request reauthentication should still verify persisted status and expiry advancement after their own final write; helper exit alone is not authorization proof.

## License

Apache-2.0
