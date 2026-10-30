# Databricks SDK — WorkspaceClient with Workload Identity Federation

`wif_client.py` builds a `WorkspaceClient` with a custom credentials strategy:

```
External IdP token endpoint  ── client_credentials (client_id, resource_id)
                                 + client_secret OR private_key_jwt assertion
      ↓  external access token
oidc_credentials_provider    ── RFC 8693 token exchange at <host>/oidc/v1/token
      ↓  Databricks token (cached & refreshed by the SDK)
WorkspaceClient              ── w.current_user.me()
```

## Run

```bash
source ../.venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # or export the variables
python wif_client.py
```

## Configuration

| Variable | Purpose |
| --- | --- |
| `EXTERNAL_TOKEN_ENDPOINT` | External IdP token endpoint |
| `EXTERNAL_CLIENT_ID` | External OAuth client |
| `EXTERNAL_CLIENT_SECRET` | Client secret (`client_secret_post`). Not used when a private key is set |
| `EXTERNAL_PRIVATE_KEY` / `EXTERNAL_PRIVATE_KEY_FILE` | PEM private key (contents or path) — enables `private_key_jwt` |
| `EXTERNAL_PRIVATE_KEY_PASSWORD` | Passphrase for an encrypted key |
| `EXTERNAL_JWT_ALG` | `RS256` (default), `PS256` or `ES256` (P-256 key) |
| `EXTERNAL_JWT_KID` / `EXTERNAL_JWT_X5T` | Assertion `kid` / `x5t` headers (Entra ID uses `x5t`) |
| `EXTERNAL_JWT_AUDIENCE` | Assertion `aud`; defaults to `EXTERNAL_TOKEN_ENDPOINT` |
| `EXTERNAL_RESOURCE_ID` | Resource the external token is issued for (becomes its `aud`) |
| `EXTERNAL_RESOURCE_PARAM` | `resource` (default) or `scope` — form field carrying the resource id |
| `DATABRICKS_HOST` | Workspace URL |
| `DATABRICKS_CLIENT_ID` | Service principal application id owning the federation policy. Blank = account-wide federation |
| `DATABRICKS_SCOPES` | Scopes for the Databricks token (space or comma separated). Passed to `WorkspaceClient(scopes=...)`; default `all-apis` |

With `private_key_jwt` the token request sends `client_assertion_type`
(`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`) and a
`client_assertion` JWT signed with the key: `iss` = `sub` = client id,
`aud` = token endpoint, a unique `jti`, and a 5-minute lifetime (RFC 7523).

The external client id deliberately uses `EXTERNAL_*` names so it never
collides with the SDK's own `DATABRICKS_CLIENT_ID`.

## Databricks prerequisites

Create a federation policy (on the service principal for WIF, or account-wide)
whose `issuer` matches the external IdP, whose `audiences` include the external
token's `aud` (usually `EXTERNAL_RESOURCE_ID`), and whose `subject` matches the
token's `sub` claim (for client-credentials tokens, typically the client/app id).

## Interactive variant: authorization code flow with a public client

`aif_authcode_client.py` gets the external token from a user login instead of
client credentials:

```
Browser → IdP authorize endpoint  ── authorization code + PKCE (S256), state, nonce
      ↓  code on loopback redirect (e.g. http://localhost:8020/callback)
IdP token endpoint                ── client_id + code_verifier (no client secret)
      ↓  user access token (or ID token)
oidc_credentials_provider         ── RFC 8693 exchange with DATABRICKS_SCOPES
      ↓
WorkspaceClient                   ── w.current_user.me()
```

```bash
cp .env.authcode.example .env.authcode   # fill in
python aif_authcode_client.py            # opens the browser
```

| Variable | Purpose |
| --- | --- |
| `EXTERNAL_DISCOVERY_URL` | IdP discovery document (or set `EXTERNAL_AUTHORIZATION_ENDPOINT` + `EXTERNAL_TOKEN_ENDPOINT`) |
| `EXTERNAL_CLIENT_ID` | Public client id |
| `EXTERNAL_REDIRECT_URI` | Loopback redirect registered with the IdP (default `http://localhost:8020/callback`) |
| `EXTERNAL_SCOPES` | Default `openid profile email`; add `offline_access` for a refresh token |
| `EXTERNAL_SUBJECT_TOKEN` | `access_token` (default) or `id_token` — which token Databricks receives |
| `EXTERNAL_RESOURCE_ID` / `EXTERNAL_RESOURCE_PARAM` | Optional resource/audience (e.g. `audience` for Auth0) |
| `EXTERNAL_LOGIN_TIMEOUT` | Seconds to wait for the browser login (default 300) |
| `DATABRICKS_HOST` / `DATABRICKS_CLIENT_ID` / `DATABRICKS_SCOPES` | As above |

When the external token expires it is renewed with the refresh token if the
IdP issued one; otherwise the browser login runs again. The federation policy
must trust the user token's issuer, audience and subject, and the subject must
map to a Databricks user.
