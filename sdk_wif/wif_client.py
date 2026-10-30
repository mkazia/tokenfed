"""WorkspaceClient with a custom credentials strategy for Databricks
Workload Identity Federation (WIF).

Flow:
  1. Fetch an access token from an external OAuth token endpoint using the
     client credentials grant (client_id + resource_id), authenticating the
     client with either a client secret or a private_key_jwt assertion.
  2. Hand that token to the SDK's oidc_credentials_provider, which exchanges
     it at the Databricks workspace token endpoint (RFC 8693 token exchange)
     and caches/refreshes the resulting Databricks token.
  3. Use the WorkspaceClient as normal.

Environment:
  EXTERNAL_TOKEN_ENDPOINT   external IdP token endpoint
  EXTERNAL_CLIENT_ID        external OAuth client id
  EXTERNAL_CLIENT_SECRET    external OAuth client secret (client_secret_post)
  EXTERNAL_RESOURCE_ID      resource the external token is issued for

  private_key_jwt client authentication (used instead of the secret when a
  private key is configured):
  EXTERNAL_PRIVATE_KEY      PEM private key contents ("\\n" escapes allowed)
  EXTERNAL_PRIVATE_KEY_FILE path to a PEM private key (alternative to above)
  EXTERNAL_PRIVATE_KEY_PASSWORD (optional) passphrase for an encrypted key
  EXTERNAL_JWT_ALG          RS256 (default), PS256 or ES256
  EXTERNAL_JWT_KID          (optional) "kid" header of the client assertion
  EXTERNAL_JWT_X5T          (optional) "x5t" header (base64url SHA-1 cert
                            thumbprint, e.g. required by Entra ID)
  EXTERNAL_JWT_AUDIENCE     (optional) assertion "aud"; defaults to the token
                            endpoint
  EXTERNAL_RESOURCE_PARAM   (optional) form field carrying the resource id:
                            "resource" (default) or "scope"
  DATABRICKS_HOST           Databricks workspace URL
  DATABRICKS_CLIENT_ID      (optional) service principal application id that
                            owns the federation policy. Leave unset for
                            account-wide token federation.
  DATABRICKS_SCOPES         (optional) space or comma separated scopes for the
                            Databricks token, e.g. "sql iam.current-user:read".
                            Defaults to "all-apis".
"""

import logging
import os
import threading
import time
import uuid
from typing import Optional

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from databricks.sdk import WorkspaceClient
from databricks.sdk.service import jobs
from databricks.sdk.credentials_provider import (
    credentials_strategy,
    oidc_credentials_provider,
)
from databricks.sdk.oidc import IdToken, IdTokenSource
from dotenv import load_dotenv
#from http.client import HTTPConnection
#import six

logger = logging.getLogger(__name__)

#HTTPConnection.debuglevel = 1
#six.moves.http_client.HTTPConnection.debuglevel = 1

# Refresh the external token this many seconds before it expires.
_EXPIRY_SKEW_SECONDS = 60

# Lifetime of a private_key_jwt client assertion.
_ASSERTION_LIFETIME_SECONDS = 300

_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Supported assertion signing algorithms and the key type each requires.
_SUPPORTED_JWT_ALGS = {
    "RS256": rsa.RSAPrivateKey,
    "PS256": rsa.RSAPrivateKey,
    "ES256": ec.EllipticCurvePrivateKey,
}


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _optional(name: str) -> Optional[str]:
    return os.environ.get(name, "").strip() or None


def load_private_key(pem: str, password: Optional[str] = None):
    """Load a PEM private key. Accepts literal "\\n" escapes so the key can be
    passed through a single-line environment variable."""
    data = pem.replace("\\n", "\n").encode()
    return serialization.load_pem_private_key(
        data, password=password.encode() if password else None
    )


class ClientCredentialsIdTokenSource(IdTokenSource):
    """IdTokenSource that obtains the subject token from an external OAuth
    token endpoint with the client credentials grant.

    The client authenticates with exactly one of:
      - client_secret: sent as client_secret_post.
      - private_key: a private_key_jwt client assertion (RFC 7523) signed with
        RS256, PS256 or ES256, carrying an optional kid and/or x5t header.

    The token is cached until shortly before it expires, so the SDK's
    validation call and its first token exchange share a single fetch.
    """

    def __init__(
        self,
        token_endpoint: str,
        client_id: str,
        resource_id: str,
        client_secret: Optional[str] = None,
        resource_param: str = "resource",
        private_key=None,
        jwt_alg: str = "RS256",
        jwt_kid: Optional[str] = None,
        jwt_x5t: Optional[str] = None,
        jwt_audience: Optional[str] = None,
    ):
        if bool(client_secret) == bool(private_key):
            raise ValueError("Configure exactly one of client_secret or private_key")
        if private_key is not None:
            key_type = _SUPPORTED_JWT_ALGS.get(jwt_alg)
            if key_type is None:
                raise ValueError(
                    f"Unsupported JWT alg {jwt_alg!r}; use one of {sorted(_SUPPORTED_JWT_ALGS)}"
                )
            if not isinstance(private_key, key_type):
                raise ValueError(f"{jwt_alg} requires an {key_type.__name__}")
            if jwt_alg == "ES256" and not isinstance(private_key.curve, ec.SECP256R1):
                raise ValueError("ES256 requires a P-256 (secp256r1) key")

        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._resource_id = resource_id
        self._resource_param = resource_param
        self._private_key = private_key
        self._jwt_alg = jwt_alg
        self._jwt_kid = jwt_kid
        self._jwt_x5t = jwt_x5t
        self._jwt_audience = jwt_audience or token_endpoint
        self._lock = threading.Lock()
        self._token = None
        self._expires_at = 0.0

    def _client_assertion(self) -> str:
        """Build a signed private_key_jwt client assertion."""
        now = int(time.time())
        headers = {}
        if self._jwt_kid:
            headers["kid"] = self._jwt_kid
        if self._jwt_x5t:
            headers["x5t"] = self._jwt_x5t
        claims = {
            "iss": self._client_id,
            "sub": self._client_id,
            "aud": self._jwt_audience,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "nbf": now,
            "exp": now + _ASSERTION_LIFETIME_SECONDS,
        }
        return jwt.encode(claims, self._private_key, algorithm=self._jwt_alg, headers=headers)

    def _client_auth_params(self) -> dict:
        if self._private_key is not None:
            return {
                "client_assertion_type": _CLIENT_ASSERTION_TYPE,
                "client_assertion": self._client_assertion(),
            }
        return {"client_secret": self._client_secret}

    def id_token(self) -> IdToken:
        with self._lock:
            if self._token and time.time() < self._expires_at - _EXPIRY_SKEW_SECONDS:
                return IdToken(jwt=self._token)

            resp = requests.post(
                self._token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    self._resource_param: self._resource_id,
                    **self._client_auth_params(),
                },
                headers={"Accept": "application/json"},
                timeout=30,
            )
            if not resp.ok:
                raise RuntimeError(
                    f"External token request failed ({resp.status_code}): {resp.text}"
                )
            body = resp.json()
            token = body.get("access_token")
            if not token:
                raise RuntimeError(f"No access_token in external token response: {body}")

            self._token = token
            self._expires_at = time.time() + int(body.get("expires_in", 300))
            logger.debug("Fetched external access token (expires_in=%s)", body.get("expires_in"))
            return IdToken(jwt=token)


def external_wif_strategy(id_token_source: IdTokenSource):
    """Build a CredentialsStrategy that federates the external token into
    Databricks via oidc_credentials_provider.

    The Databricks token is requested with the scopes from the client config
    (``WorkspaceClient(scopes=[...])`` or a profile's ``scopes``). The SDK
    falls back to the broad ``all-apis`` scope when none are configured.
    """

    @credentials_strategy("external-client-credentials-wif", ["host"])
    def strategy(cfg):
        if cfg.scopes:
            logger.debug("Requesting Databricks token with scopes: %s", cfg.get_scopes_as_string())
        else:
            logger.warning(
                "No scopes configured; requesting Databricks token with the default %r scope",
                cfg.get_scopes_as_string(),
            )
        # oidc_credentials_provider swallows token-source errors and returns
        # None ("not configured"). Fetch once up front so a misconfigured IdP
        # surfaces its real error; the result is cached for the SDK's calls.
        id_token_source.id_token()
        # Sends cfg.get_scopes_as_string() as the token exchange "scope".
        return oidc_credentials_provider(cfg, id_token_source)

    return strategy


def build_token_source_from_env() -> ClientCredentialsIdTokenSource:
    """Build the external token source. A configured private key selects
    private_key_jwt; otherwise EXTERNAL_CLIENT_SECRET is required."""
    pem = _optional("EXTERNAL_PRIVATE_KEY")
    key_file = _optional("EXTERNAL_PRIVATE_KEY_FILE")
    if pem and key_file:
        raise RuntimeError("Set only one of EXTERNAL_PRIVATE_KEY or EXTERNAL_PRIVATE_KEY_FILE")
    if key_file:
        with open(key_file) as f:
            pem = f.read()

    if pem:
        auth_kwargs = {
            "private_key": load_private_key(pem, _optional("EXTERNAL_PRIVATE_KEY_PASSWORD")),
            "jwt_alg": (_optional("EXTERNAL_JWT_ALG") or "RS256").upper(),
            "jwt_kid": _optional("EXTERNAL_JWT_KID"),
            "jwt_x5t": _optional("EXTERNAL_JWT_X5T"),
            "jwt_audience": _optional("EXTERNAL_JWT_AUDIENCE"),
        }
    else:
        auth_kwargs = {"client_secret": _require("EXTERNAL_CLIENT_SECRET")}

    return ClientCredentialsIdTokenSource(
        token_endpoint=_require("EXTERNAL_TOKEN_ENDPOINT"),
        client_id=_require("EXTERNAL_CLIENT_ID"),
        resource_id=_require("EXTERNAL_RESOURCE_ID"),
        resource_param=_optional("EXTERNAL_RESOURCE_PARAM") or "resource",
        **auth_kwargs,
    )


def build_workspace_client() -> WorkspaceClient:
    token_source = build_token_source_from_env()
    # client_id is the Databricks service principal for WIF. Passed explicitly
    # so it is never confused with the external EXTERNAL_CLIENT_ID.
    # The SDK has no environment variable for scopes, so read our own. Space or
    # comma separated; the SDK de-duplicates and sorts them.
    scopes = _optional("DATABRICKS_SCOPES")
    return WorkspaceClient(
        host=_require("DATABRICKS_HOST"),
        client_id=os.environ.get("DATABRICKS_CLIENT_ID", "").strip() or None,
        scopes=scopes.replace(",", " ").split() if scopes else None,
        credentials_strategy=external_wif_strategy(token_source),
    )


def main():
    load_dotenv()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

    w = build_workspace_client()
    print(f"auth_type: {w.config.auth_type}")

    me = w.current_user.me()
    print(f"current user: {me.user_name} (id={me.id})")


if __name__ == "__main__":
    main()
