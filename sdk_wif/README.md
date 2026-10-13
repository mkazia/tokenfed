# Databricks SDK — WorkspaceClient with Workload Identity Federation

`wif_client.py` builds a `WorkspaceClient` with a custom credentials strategy:

```
External IdP token endpoint  ── client_credentials (client_id, client_secret, resource_id)
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
| `EXTERNAL_CLIENT_ID` / `EXTERNAL_CLIENT_SECRET` | External OAuth client |
| `EXTERNAL_RESOURCE_ID` | Resource the external token is issued for (becomes its `aud`) |
| `EXTERNAL_RESOURCE_PARAM` | `resource` (default) or `scope` — form field carrying the resource id |
| `DATABRICKS_HOST` | Workspace URL |
| `DATABRICKS_CLIENT_ID` | Service principal application id owning the federation policy. Blank = account-wide federation |

The external client id deliberately uses `EXTERNAL_*` names so it never
collides with the SDK's own `DATABRICKS_CLIENT_ID`.

## Databricks prerequisites

Create a federation policy (on the service principal for WIF, or account-wide)
whose `issuer` matches the external IdP, whose `audiences` include the external
token's `aud` (usually `EXTERNAL_RESOURCE_ID`), and whose `subject` matches the
token's `sub` claim (for client-credentials tokens, typically the client/app id).
