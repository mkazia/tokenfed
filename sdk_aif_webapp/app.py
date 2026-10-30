"""Web app version of the authorization code flow token federation example.

Flow:
  1. The user logs in at the external IdP with the authorization code grant
     as a public client with PKCE (S256). No client secret is used.
  2. The user's tokens are kept server-side; the session cookie only holds a
     random session id.
  3. Each logged-in user gets a WorkspaceClient whose credentials strategy
     hands the user's external token to the SDK's oidc_credentials_provider,
     which exchanges it at the Databricks token endpoint (RFC 8693) with the
     configured scopes and caches the Databricks token.
  4. When the external token expires it is renewed with the refresh token if
     one was issued; otherwise the user is sent through the login again.

Environment: see .env.example.
"""

import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import OAuth
from databricks.sdk import WorkspaceClient
from databricks.sdk.credentials_provider import (
    credentials_strategy,
    oidc_credentials_provider,
)
from databricks.sdk.oidc import IdToken, IdTokenSource
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, session, url_for

load_dotenv()
logger = logging.getLogger(__name__)

# Refresh the external token this many seconds before it expires.
_EXPIRY_SKEW_SECONDS = 60


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {name}. "
            f"Copy .env.example to .env and fill it in."
        )
    return value


def _optional(name: str) -> Optional[str]:
    return os.environ.get(name, "").strip() or None


# --- Configuration ---------------------------------------------------------
# Without FLASK_SECRET_KEY a random key is used, so sessions end on restart.
SECRET_KEY = _optional("FLASK_SECRET_KEY") or secrets.token_hex(32)

EXTERNAL_DISCOVERY_URL = _require("EXTERNAL_DISCOVERY_URL")
EXTERNAL_CLIENT_ID = _require("EXTERNAL_CLIENT_ID")
EXTERNAL_REDIRECT_URI = _optional("EXTERNAL_REDIRECT_URI") or "http://localhost:5000/callback"
EXTERNAL_SCOPES = _optional("EXTERNAL_SCOPES") or "openid profile email"
EXTERNAL_SUBJECT_TOKEN = _optional("EXTERNAL_SUBJECT_TOKEN") or "access_token"
if EXTERNAL_SUBJECT_TOKEN not in ("access_token", "id_token"):
    raise RuntimeError("EXTERNAL_SUBJECT_TOKEN must be 'access_token' or 'id_token'")
# Optional resource/audience, sent on the authorize, token and refresh requests.
_resource_id = _optional("EXTERNAL_RESOURCE_ID")
RESOURCE_PARAMS = (
    {(_optional("EXTERNAL_RESOURCE_PARAM") or "resource"): _resource_id} if _resource_id else {}
)

DATABRICKS_HOST = _require("DATABRICKS_HOST").rstrip("/")
DATABRICKS_CLIENT_ID = _optional("DATABRICKS_CLIENT_ID")
_scopes = _optional("DATABRICKS_SCOPES")
DATABRICKS_SCOPES = _scopes.replace(",", " ").split() if _scopes else None


class LoginRequired(Exception):
    """The user's external token can no longer be renewed without a login."""


class UserTokenSource(IdTokenSource):
    """IdTokenSource holding one user's external tokens from the
    authorization code flow.

    Returns the cached token until shortly before it expires, then renews it
    with the refresh token (public client: client_id only). Raises
    LoginRequired when no refresh token was issued or it is rejected.
    """

    def __init__(self, token_endpoint: str, token: dict):
        self._token_endpoint = token_endpoint
        self._lock = threading.Lock()
        self._token = None
        self._refresh_token = None
        self._expires_at = 0.0
        self._store(token)

    def _store(self, body: dict):
        token = body.get(EXTERNAL_SUBJECT_TOKEN)
        if not token:
            raise LoginRequired(f"No {EXTERNAL_SUBJECT_TOKEN} in external token response")
        self._token = token
        # Keep the previous refresh token if the IdP does not rotate it.
        self._refresh_token = body.get("refresh_token") or self._refresh_token
        if body.get("expires_at"):
            self._expires_at = float(body["expires_at"])
        else:
            self._expires_at = time.time() + int(body.get("expires_in", 300))

    def id_token(self) -> IdToken:
        with self._lock:
            if time.time() < self._expires_at - _EXPIRY_SKEW_SECONDS:
                return IdToken(jwt=self._token)
            if not self._refresh_token:
                raise LoginRequired("External token expired and no refresh token was issued")

            resp = requests.post(
                self._token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self._refresh_token,
                    "client_id": EXTERNAL_CLIENT_ID,
                    **RESOURCE_PARAMS,
                },
                headers={"Accept": "application/json"},
                timeout=30,
            )
            if not resp.ok:
                raise LoginRequired(f"Refresh token rejected ({resp.status_code}): {resp.text}")
            self._store(resp.json())
            logger.debug("Refreshed external %s", EXTERNAL_SUBJECT_TOKEN)
            return IdToken(jwt=self._token)


def external_wif_strategy(id_token_source: IdTokenSource):
    """Build a CredentialsStrategy that federates the user's external token
    into Databricks via oidc_credentials_provider.

    The Databricks token is requested with the scopes from the client config
    (``WorkspaceClient(scopes=[...])``). The SDK falls back to the broad
    ``all-apis`` scope when none are configured.
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
        # None ("not configured"). Fetch once up front so the real error
        # surfaces.
        id_token_source.id_token()
        # Sends cfg.get_scopes_as_string() as the token exchange "scope".
        return oidc_credentials_provider(cfg, id_token_source)

    return strategy


@dataclass
class UserSession:
    token_source: UserTokenSource
    client: WorkspaceClient
    user: dict = field(default_factory=dict)


# Server-side session store: session id -> UserSession. In memory, so it is
# per process and cleared on restart; use a shared store to run several
# workers.
_sessions: dict[str, UserSession] = {}
_sessions_lock = threading.Lock()


def _current_session() -> Optional[UserSession]:
    sid = session.get("sid")
    with _sessions_lock:
        return _sessions.get(sid) if sid else None


def _end_session():
    sid = session.pop("sid", None)
    if sid:
        with _sessions_lock:
            _sessions.pop(sid, None)
    session.clear()


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Public client: no client secret, token endpoint auth method "none", PKCE
# (S256) enforced. Authlib checks state and the ID token's signature and nonce.
oauth = OAuth(app)
oauth.register(
    name="oidc",
    client_id=EXTERNAL_CLIENT_ID,
    client_secret=None,
    server_metadata_url=EXTERNAL_DISCOVERY_URL,
    client_kwargs={
        "scope": EXTERNAL_SCOPES,
        "code_challenge_method": "S256",
        "token_endpoint_auth_method": "none",
    },
)


@app.errorhandler(OAuthError)
def oauth_error(e):
    """Login failures: state mismatch, IdP error responses, ID token checks."""
    return jsonify(stage="login", error=e.error, description=e.description), 400


@app.route("/")
def index():
    current = _current_session()
    return render_template(
        "index.html",
        user=current.user if current else None,
        scopes=" ".join(DATABRICKS_SCOPES) if DATABRICKS_SCOPES else "all-apis (default)",
    )


@app.route("/login")
def login():
    return oauth.oidc.authorize_redirect(EXTERNAL_REDIRECT_URI, **RESOURCE_PARAMS)


@app.route("/callback")
def callback():
    token = oauth.oidc.authorize_access_token(**RESOURCE_PARAMS)
    token_source = UserTokenSource(
        token_endpoint=oauth.oidc.load_server_metadata()["token_endpoint"],
        token=token,
    )
    try:
        client = WorkspaceClient(
            host=DATABRICKS_HOST,
            client_id=DATABRICKS_CLIENT_ID,
            scopes=DATABRICKS_SCOPES,
            credentials_strategy=external_wif_strategy(token_source),
        )
    except Exception as e:
        return jsonify(stage="databricks-client", error=str(e)), 502

    # New session id on every login; the cookie never carries tokens.
    _end_session()
    sid = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[sid] = UserSession(token_source, client, token.get("userinfo") or {})
    session["sid"] = sid
    return redirect(url_for("index"))


@app.route("/databricks")
def databricks():
    """Call a Databricks API as the logged-in user."""
    current = _current_session()
    if not current:
        return redirect(url_for("login"))

    # Renew the external token now if needed, so an expired login sends the
    # user back through the IdP instead of failing inside the SDK.
    try:
        current.token_source.id_token()
    except LoginRequired as e:
        logger.info("Login required: %s", e)
        _end_session()
        return redirect(url_for("login"))

    try:
        me = current.client.current_user.me()
    except Exception as e:
        return jsonify(stage="databricks", error=str(e)), 502

    return jsonify(
        auth_type=current.client.config.auth_type,
        scopes=current.client.config.get_scopes_as_string(),
        current_user=me.as_dict(),
    )


@app.route("/logout")
def logout():
    _end_session()
    return redirect(url_for("index"))


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    app.run(host="localhost", port=int(os.environ.get("PORT", 5000)))
