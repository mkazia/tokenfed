# Databricks SDK token federation — web app (authorization code flow)

Web app version of [`sdk_wif/wif_authcode_client.py`](../sdk_wif/wif_authcode_client.py).
Users log in at an external IdP as a **public client** (authorization code +
PKCE), and the app calls Databricks **as that user** through the Databricks
Python SDK.

```
Browser → /login → IdP authorize   ── authorization code + PKCE (S256), state, nonce
      ↓  /callback
IdP token endpoint                 ── client_id + code_verifier (no client secret)
      ↓  user access token (or ID token), stored server-side
WorkspaceClient per user           ── credentials strategy → oidc_credentials_provider
      ↓  RFC 8693 exchange with DATABRICKS_SCOPES (token cached per user)
/databricks                        ── w.current_user.me()
```

## Run

```bash
source ../.venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in
python app.py          # http://localhost:5000
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `FLASK_SECRET_KEY` | Signs the session cookie. Random if blank (sessions end on restart) |
| `EXTERNAL_DISCOVERY_URL` | IdP discovery document |
| `EXTERNAL_CLIENT_ID` | Public client id |
| `EXTERNAL_REDIRECT_URI` | Registered redirect URI (default `http://localhost:5000/callback`) |
| `EXTERNAL_SCOPES` | Default `openid profile email`; add `offline_access` for a refresh token |
| `EXTERNAL_SUBJECT_TOKEN` | `access_token` (default) or `id_token` — which token Databricks receives |
| `EXTERNAL_RESOURCE_ID` / `EXTERNAL_RESOURCE_PARAM` | Optional resource/audience (e.g. `audience` for Auth0) |
| `DATABRICKS_HOST` | Workspace URL |
| `DATABRICKS_CLIENT_ID` | Service principal application id owning the federation policy. Blank = account-wide federation |
| `DATABRICKS_SCOPES` | Scopes for the Databricks token (space or comma separated); default `all-apis` |

## How sessions work

- Tokens never go in the cookie. The app keeps each user's tokens and
  `WorkspaceClient` in an in-memory store; the cookie only holds a random
  session id, replaced on every login.
- When the external token expires the app renews it with the refresh token
  (client_id only). If none was issued, or it is rejected, the user is sent
  back through `/login`.
- The store is per process and lost on restart. To run several workers, or
  to survive restarts, move it to a shared store (e.g. Redis) and encrypt the
  tokens at rest.

## Prerequisites

- A **public** OIDC client at the IdP with the redirect URI registered and
  PKCE allowed.
- A Databricks federation policy that trusts the user token's issuer,
  audience and subject, where the subject maps to a Databricks user.
