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

## Required Headers

All authenticated requests require these headers:

```
Authorization: Bearer <access_token>
x-pm-uid: <session_uid>
x-pm-appversion: linux-vpn@X.Y.Z
User-Agent: ProtonVPN/X.Y.Z (Linux; Ubuntu)
Content-Type: application/json
```

**Important**: Using a web client version (like `web-vpn-settings@X.Y.Z`) may trigger CAPTCHA challenges. Always use the Linux client version format.

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
