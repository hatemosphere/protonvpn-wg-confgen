# API Reference Implementation

This project's API integration was developed by reverse-engineering ProtonVPN's authentication and VPN APIs. The implementation is based on patterns from these official Proton libraries:

## Authentication (SRP Protocol)
- **[ProtonMail/proton-python-client](https://github.com/ProtonMail/proton-python-client)** - Python implementation of Proton's SRP authentication
  - Reference for: `/auth/info`, `/auth`, `/auth/2fa`, `/auth/refresh` endpoints
  - SRP protocol implementation patterns
- **[ProtonMail/go-srp](https://github.com/ProtonMail/go-srp)** - Go SRP library (direct dependency)

## VPN API
- **[ProtonVPN/python-proton-vpn-api-core](https://github.com/ProtonVPN/python-proton-vpn-api-core)** - Official Python VPN API client
  - Reference for: `/vpn/v1/certificate`, `/vpn/v1/logicals`, `/vpn/v1/sessions` endpoints
  - Server filtering and selection patterns
  - Certificate request format (`Duration`, `Features`)

## Key Generation
- **[ProtonVPN/go-vpn-lib](https://github.com/ProtonVPN/go-vpn-lib)** - Ed25519 to X25519 key conversion (direct dependency)

## Client Version
- **[ProtonVPN/proton-vpn-gtk-app](https://github.com/ProtonVPN/proton-vpn-gtk-app)** - Official Linux client
  - Source for `x-pm-appversion` header value (fetched dynamically at build time)

## API Endpoints Used

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/core/v4/auth/info` | POST | Get SRP authentication parameters |
| `/core/v4/auth` | POST | Authenticate with SRP proofs |
| `/core/v4/auth/2fa` | POST | Submit 2FA code for session upgrade |
| `/auth/refresh` | POST | Refresh session tokens |
| `/vpn/v1/certificate` | POST | Generate WireGuard certificate |
| `/vpn/v1/logicals` | GET | List available VPN servers |

## Certificate Request Format

The certificate request to `/vpn/v1/certificate` uses the following format:

```json
{
  "ClientPublicKey": "<PEM-encoded public key>",
  "ClientPublicKeyMode": "EC",
  "Mode": "persistent",
  "DeviceName": "<device name>",
  "Duration": "<duration in minutes> min",
  "Features": {
    "NetShieldLevel": 0,
    "RandomNAT": false,
    "PortForwarding": false,
    "SplitTCP": true
  }
}
```

`Mode` is one of `session` or `persistent` (see `WireGuardConfigurationSection/Certificate.ts` in WebClients). Omitting it - as the official Linux client does for every connection - yields a session certificate: not registered on the account and absent from `GET /vpn/v1/certificate/all?Mode=persistent`. `persistent` backs the dashboard's saved configuration list, which is the only place such configs can be revoked.

`Duration` is a request, not a guarantee; the granted expiry is returned as `ExpirationTime`. Observed against the live API (2026-07-29):

| Mode | Requested | Granted |
|------|-----------|---------|
| session | 9 min or less | error, code 2001 `Certificate duration must be at least 10 minutes` |
| session | 10m / 30m / 8h / 3d / 10080m (7d) | honored exactly |
| session | 10081m / 8d / 30d / 365d | 10080m (7d), silently clamped with no error |
| persistent | 365d | 365d |

So session certificates are bounded at [10 min, 7 days]. The lower bound is enforced with a real error; the upper bound is a silent clamp, which is why this client rejects `-duration` over 7d when `-no-save` is set rather than letting a 365d request quietly become 7d.

Note that the "the API does not allow intervals shorter than 1 day" comment in `python-proton-vpn-api-core`'s `fetcher.py` does not hold - sub-day durations are accepted down to 10 minutes. Likewise its 7-day `VPNPubkeyCredentials.REFRESH_INTERVAL` is that client's own refresh cadence and coincides with, but does not explain, the server-side cap.

### Feature Keys

| Key | Type | Description |
|-----|------|-------------|
| `NetShieldLevel` | int | NetShield ad/malware blocking (0=off, 1=malware, 2=ads+malware) |
| `RandomNAT` | bool | Moderate NAT / Random NAT for gaming |
| `PortForwarding` | bool | Port forwarding support |
| `SplitTCP` | bool | VPN Accelerator (performance optimization) |

## API Response Codes

**Official sources:**
- [ProtonMail/protoncore_android - ResponseCodes.kt](https://github.com/ProtonMail/protoncore_android/blob/main/network/domain/src/main/kotlin/me/proton/core/network/domain/ResponseCodes.kt) - Kotlin constants (authoritative)
- [ProtonMail/proton-python-client - README.md](https://github.com/ProtonMail/proton-python-client#error-handling) - Python client error handling
- [ProtonMail/proton-python-client - api.py](https://github.com/ProtonMail/proton-python-client/blob/master/proton/api.py) - Python API implementation

### Success Codes
| Code | Constant | Meaning |
|------|----------|---------|
| 1000 | OK | Success |
| 1001 | - | Success (multi-status) |

### Authentication Errors
| Code | Constant | Meaning |
|------|----------|---------|
| 8002 | PASSWORD_WRONG | Incorrect password |
| 8100 | AUTH_SWITCH_TO_SSO | Switch to SSO authentication |
| 8101 | AUTH_SWITCH_TO_SRP | Switch to SRP authentication |
| 9001 | HUMAN_VERIFICATION_REQUIRED | CAPTCHA/human verification required |
| 9002 | DEVICE_VERIFICATION_REQUIRED | Device verification required |
| 9101 | SCOPE_REAUTH_LOCKED | Scope re-authentication locked |
| 9102 | SCOPE_REAUTH_PASSWORD | Scope re-authentication requires password |

### Account Errors
| Code | Constant | Meaning |
|------|----------|---------|
| 10001 | ACCOUNT_FAILED_GENERIC | Generic account failure |
| 10002 | ACCOUNT_DELETED | Account has been deleted |
| 10003 | ACCOUNT_DISABLED | Account has been disabled |

### Version Errors
| Code | Constant | Meaning |
|------|----------|---------|
| 5003 | APP_VERSION_BAD | App version no longer supported |
| 5005 | API_VERSION_INVALID | API version invalid |
| 5099 | APP_VERSION_NOT_SUPPORTED_FOR_EXTERNAL_ACCOUNTS | App version not supported for external accounts |

### Other Errors
| Code | Constant | Meaning |
|------|----------|---------|
| 6001 | BODY_PARSE_FAILURE | Request body parse failure |
| 12081 | USER_CREATE_NAME_INVALID | Invalid username during creation |
| 12087 | USER_CREATE_TOKEN_INVALID | Invalid token during user creation |

### VPN-Specific Codes (observed, not in official docs)
| Code | Meaning | Notes |
|------|---------|-------|
| 9100 | 2FA required for VPN | VPN certificate endpoint requires 2FA-authenticated session |
| 10013 | Mailbox password required | Legacy 2-password mode (proton-python-client says "RefreshToken invalid") |

**Note:** Codes 9100 and 10013 were observed during VPN operations but are not documented in the official protoncore_android library. Their meanings may vary by context.

## Request Format

Requests reproduce the official Linux client byte for byte. Recorded from Proton's own packages on Ubuntu 24.04 (api-core 5.8.3, aiohttp 3.9.1, OpenSSL 3.0.13):

```
POST /auth/2fa HTTP/1.1
Host: vpn-api.proton.me
x-pm-appversion: linux-vpn-gui@5.8.3+x86-64
User-Agent: ProtonVPN/5.8.3 (Linux; ubuntu/24.04)
x-pm-uid: <session uid>
Authorization: Bearer <access token>
x-pm-timezone: Europe/Zurich
Accept: */*
Accept-Encoding: gzip, deflate
Content-Length: 27
Content-Type: application/json

{"TwoFactorCode": "123456"}
```

- **`x-pm-appversion`** is `linux-vpn-gui@<version>+<arch>`. The version is `python-proton-vpn-api-core`'s, not the GTK app's, and the architecture is `platform.machine()` with underscores as hyphens. Both headers are built in `SessionHolder` (`proton/vpn/core/session_holder.py`). Until v0.14.0 this tool sent `linux-vpn@<GTK app version>`, which the official client does not use.
- **Order and spelling** are aiohttp's: session headers, per-request headers, aiohttp defaults, then body headers. Custom headers are lowercase.
- **`x-pm-uid` and `Authorization`** appear only on authenticated requests, `Content-Length` and `Content-Type` only with a body.
- **`x-pm-timezone`** is the IANA name `/etc/localtime` points to, omitted when unresolvable. python-proton-core's own calls, the `/tests/ping` transport probe and `/auth/refresh`, do not carry it.
- **`x-pm-locale`** is sent by the official client only with a non-English catalog active, so it is not sent here.
- **Bodies** are Python `json.dumps` output: `", "` and `": "` separators, keys in insertion order, non-ASCII escaped.
- **Connection**: HTTP/1.1, one connection per request, TLS ClientHello as OpenSSL 3.0.13 produces it under aiohttp's certificate-pinning path.
- **2FA** is always a separate `POST /auth/2fa` after `/auth`, never a field of the `/auth` body.

`make parity-goldens` re-records all of this from the official client; `go test` fails on any divergence.

**Important**: Using a web client version (like `web-vpn-settings@X.Y.Z`) may trigger CAPTCHA challenges.

## Token Refresh

The token refresh endpoint expects:

```json
{
  "ResponseType": "token",
  "GrantType": "refresh_token",
  "RefreshToken": "<refresh_token>",
  "RedirectURI": "http://protonmail.ch"
}
```

## Local Reference Libraries

For debugging and verification, reference implementations are cloned in `.debug-libs/`:
- `proton-python-client` - SRP authentication reference
- `python-proton-vpn-api-core` - VPN API reference
- `proton-vpn-gtk-app` - Linux client reference
