"""WorkspaceClient with a custom credentials strategy for Databricks token
federation, where the external token comes from an interactive
authorization code flow with a public client.

Flow:
  1. Open the browser at the external IdP's authorization endpoint using the
     authorization code grant with PKCE (S256). The client is public, so no
     client secret is used anywhere.
  2. Receive the code on a local loopback redirect URI and exchange it at the
     IdP token endpoint (client_id + code_verifier).
  3. Hand the user's access token (or ID token) to the SDK's
     oidc_credentials_provider, which exchanges it at the Databricks token
     endpoint (RFC 8693) with the configured scopes, then caches and refreshes
     the Databricks token.
  4. When the external token expires, use its refresh token if one was issued;
     otherwise run the browser flow again.

Environment:
  EXTERNAL_DISCOVERY_URL    IdP .well-known/openid-configuration URL. Supplies
                            the authorization and token endpoints.
  EXTERNAL_AUTHORIZATION_ENDPOINT / EXTERNAL_TOKEN_ENDPOINT
                            (optional) explicit endpoints instead of discovery
  EXTERNAL_CLIENT_ID        public OAuth client id
  EXTERNAL_REDIRECT_URI     loopback redirect URI registered with the IdP,
                            default http://localhost:8020/callback
  EXTERNAL_SCOPES           scopes for the external token, default
                            "openid profile email". Add "offline_access" to
                            get a refresh token if the IdP allows it.
  EXTERNAL_SUBJECT_TOKEN    which IdP token to exchange: "access_token"
                            (default) or "id_token"
  EXTERNAL_RESOURCE_ID      (optional) resource/audience for the external token
  EXTERNAL_RESOURCE_PARAM   (optional) form field carrying it: "resource"
                            (default) or e.g. "audience" (Auth0)
  EXTERNAL_LOGIN_TIMEOUT    (optional) seconds to wait for the browser login,
                            default 300
  DATABRICKS_HOST           Databricks workspace URL
  DATABRICKS_SCOPES         (optional) space or comma separated scopes for the
                            Databricks token. Defaults to "all-apis".
"""

import base64
import hashlib
import logging
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

import jwt
import requests
from databricks.sdk import WorkspaceClient
from databricks.sdk.credentials_provider import (
    credentials_strategy,
    oidc_credentials_provider,
)
from databricks.sdk.oidc import IdToken, IdTokenSource
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# Refresh the external token this many seconds before it expires.
_EXPIRY_SKEW_SECONDS = 60


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _optional(name: str) -> Optional[str]:
    return os.environ.get(name, "").strip() or None


def _pkce_pair() -> tuple[str, str]:
    """Return a (code_verifier, S256 code_challenge) pair (RFC 7636)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _wait_for_redirect(redirect_uri: str, timeout: int) -> dict:
    """Serve one request on the loopback redirect URI and return its query
    parameters."""
    parsed = urllib.parse.urlparse(redirect_uri)
    if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError(f"Redirect URI must be an http loopback address, got {redirect_uri!r}")
    result = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            if url.path != parsed.path:
                self.send_response(404)
                self.end_headers()
                return
            result.update(dict(urllib.parse.parse_qsl(url.query)))
            ok = "code" in result
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            message = "Login complete. You can close this window." if ok else "Login failed. Check the terminal."
            self.wfile.write(f"<html><body><p>{message}</p></body></html>".encode())

    server = HTTPServer((parsed.hostname, parsed.port or 80), Handler)
    server.timeout = 1
    deadline = time.time() + timeout
    try:
        while not result and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if not result:
        raise TimeoutError(f"No redirect received on {redirect_uri} within {timeout}s")
    return result


class AuthorizationCodeIdTokenSource(IdTokenSource):
    """IdTokenSource that obtains the subject token from an external IdP with
    the authorization code grant, as a public client with PKCE.

    The first call opens the browser for the user to log in. The token is
    cached until shortly before it expires, then renewed with the refresh
    token if one was issued, or with a new browser login.
    """

    def __init__(
        self,
        authorization_endpoint: str,
        token_endpoint: str,
        client_id: str,
        redirect_uri: str = "http://localhost:8020/callback",
        scopes: str = "openid profile email",
        subject_token: str = "access_token",
        resource_id: Optional[str] = None,
        resource_param: str = "resource",
        login_timeout: int = 300,
    ):
        if subject_token not in ("access_token", "id_token"):
            raise ValueError("subject_token must be 'access_token' or 'id_token'")
        if subject_token == "id_token" and "openid" not in scopes.split():
            raise ValueError("subject_token=id_token requires the 'openid' scope")
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._subject_token = subject_token
        self._resource_id = resource_id
        self._resource_param = resource_param
        self._login_timeout = login_timeout
        self._lock = threading.Lock()
        self._token = None
        self._refresh_token = None
        self._expires_at = 0.0

    def _resource_params(self) -> dict:
        return {self._resource_param: self._resource_id} if self._resource_id else {}

    def _post_token(self, data: dict) -> dict:
        # Public client: identified by client_id only, no client secret.
        resp = requests.post(
            self._token_endpoint,
            data={"client_id": self._client_id, **self._resource_params(), **data},
            headers={"Accept": "application/json"},
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(f"External token request failed ({resp.status_code}): {resp.text}")
        return resp.json()

    def _login(self) -> dict:
        """Run the browser authorization code flow and return the token response."""
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "scope": self._scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            **self._resource_params(),
        }
        url = f"{self._authorization_endpoint}?{urllib.parse.urlencode(params)}"
        print(f"Opening the browser to log in. If it does not open, visit:\n{url}", flush=True)
        webbrowser.open(url)

        callback = _wait_for_redirect(self._redirect_uri, self._login_timeout)
        if callback.get("state") != state:
            raise RuntimeError("State mismatch in authorization response")
        if "error" in callback:
            raise RuntimeError(
                f"Authorization failed: {callback['error']}: {callback.get('error_description', '')}"
            )

        body = self._post_token(
            {
                "grant_type": "authorization_code",
                "code": callback["code"],
                "redirect_uri": self._redirect_uri,
                "code_verifier": verifier,
            }
        )
        id_token = body.get("id_token")
        if id_token:
            # Databricks verifies the signature during the exchange; here we
            # only bind the ID token to this login.
            claims = jwt.decode(id_token, options={"verify_signature": False})
            if claims.get("nonce") != nonce:
                raise RuntimeError("Nonce mismatch in ID token")
        return body

    def _refresh(self) -> Optional[dict]:
        try:
            return self._post_token(
                {"grant_type": "refresh_token", "refresh_token": self._refresh_token}
            )
        except RuntimeError as e:
            logger.info("Refresh token rejected, logging in again: %s", e)
            return None

    def id_token(self) -> IdToken:
        with self._lock:
            if self._token and time.time() < self._expires_at - _EXPIRY_SKEW_SECONDS:
                return IdToken(jwt=self._token)

            body = self._refresh() if self._refresh_token else None
            if body is None:
                body = self._login()

            token = body.get(self._subject_token)
            if not token:
                raise RuntimeError(
                    f"No {self._subject_token} in external token response; "
                    f"check EXTERNAL_SUBJECT_TOKEN and EXTERNAL_SCOPES"
                )
            self._token = token
            # Keep the previous refresh token if the IdP does not rotate it.
            self._refresh_token = body.get("refresh_token") or self._refresh_token
            self._expires_at = time.time() + int(body.get("expires_in", 300))
            logger.debug(
                "Obtained external %s (expires_in=%s, refresh_token=%s)",
                self._subject_token,
                body.get("expires_in"),
                bool(self._refresh_token),
            )
            return IdToken(jwt=token)


def external_aif_strategy(id_token_source: IdTokenSource):
    """Build a CredentialsStrategy that federates the external token into
    Databricks via oidc_credentials_provider.

    The Databricks token is requested with the scopes from the client config
    (``WorkspaceClient(scopes=[...])`` or a profile's ``scopes``). The SDK
    falls back to the broad ``all-apis`` scope when none are configured.
    """

    @credentials_strategy("external-authorization-code-wif", ["host"])
    def strategy(cfg):
        if cfg.scopes:
            logger.debug("Requesting Databricks token with scopes: %s", cfg.get_scopes_as_string())
        else:
            logger.warning(
                "No scopes configured; requesting Databricks token with the default %r scope",
                cfg.get_scopes_as_string(),
            )
        # oidc_credentials_provider swallows token-source errors and returns
        # None ("not configured"). Log in once up front so a failed login
        # surfaces its real error; the token is cached for the SDK's calls.
        id_token_source.id_token()
        # Sends cfg.get_scopes_as_string() as the token exchange "scope".
        return oidc_credentials_provider(cfg, id_token_source)

    return strategy


def build_token_source_from_env() -> AuthorizationCodeIdTokenSource:
    authorization_endpoint = _optional("EXTERNAL_AUTHORIZATION_ENDPOINT")
    token_endpoint = _optional("EXTERNAL_TOKEN_ENDPOINT")
    if not (authorization_endpoint and token_endpoint):
        discovery = requests.get(_require("EXTERNAL_DISCOVERY_URL"), timeout=15)
        discovery.raise_for_status()
        metadata = discovery.json()
        authorization_endpoint = authorization_endpoint or metadata["authorization_endpoint"]
        token_endpoint = token_endpoint or metadata["token_endpoint"]

    return AuthorizationCodeIdTokenSource(
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        client_id=_require("EXTERNAL_CLIENT_ID"),
        redirect_uri=_optional("EXTERNAL_REDIRECT_URI") or "http://localhost:8020/callback",
        scopes=_optional("EXTERNAL_SCOPES") or "openid profile email",
        subject_token=_optional("EXTERNAL_SUBJECT_TOKEN") or "access_token",
        resource_id=_optional("EXTERNAL_RESOURCE_ID"),
        resource_param=_optional("EXTERNAL_RESOURCE_PARAM") or "resource",
        login_timeout=int(_optional("EXTERNAL_LOGIN_TIMEOUT") or 300),
    )


def build_workspace_client() -> WorkspaceClient:
    token_source = build_token_source_from_env()
    # The SDK has no environment variable for scopes, so read our own. Space or
    # comma separated; the SDK de-duplicates and sorts them.
    scopes = _optional("DATABRICKS_SCOPES")
    # client_id is the Databricks service principal for WIF. Passed explicitly
    # so it is never confused with the external EXTERNAL_CLIENT_ID.
    return WorkspaceClient(
        host=_require("DATABRICKS_HOST"),
        scopes=scopes.replace(",", " ").split() if scopes else None,
        credentials_strategy=external_aif_strategy(token_source),
    )


def main():
    load_dotenv(os.environ.get("ENV_FILE", ".env.authcode"))
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

    w = build_workspace_client()
    print(f"auth_type: {w.config.auth_type}")

    me = w.current_user.me()
    print(f"current user: {me.user_name} (id={me.id})")


if __name__ == "__main__":
    main()
