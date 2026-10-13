"""WorkspaceClient with a custom credentials strategy for Databricks
Workload Identity Federation (WIF).

Flow:
  1. Fetch an access token from an external OAuth token endpoint using the
     client credentials grant (client_id + client_secret + resource_id).
  2. Hand that token to the SDK's oidc_credentials_provider, which exchanges
     it at the Databricks workspace token endpoint (RFC 8693 token exchange)
     and caches/refreshes the resulting Databricks token.
  3. Use the WorkspaceClient as normal.

Environment:
  EXTERNAL_TOKEN_ENDPOINT   external IdP token endpoint
  EXTERNAL_CLIENT_ID        external OAuth client id
  EXTERNAL_CLIENT_SECRET    external OAuth client secret
  EXTERNAL_RESOURCE_ID      resource the external token is issued for
  EXTERNAL_RESOURCE_PARAM   (optional) form field carrying the resource id:
                            "resource" (default) or "scope"
  DATABRICKS_HOST           Databricks workspace URL
  DATABRICKS_CLIENT_ID      (optional) service principal application id that
                            owns the federation policy. Leave unset for
                            account-wide token federation.
"""

import logging
import os
import threading
import time

import requests
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


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


class ClientCredentialsIdTokenSource(IdTokenSource):
    """IdTokenSource that obtains the subject token from an external OAuth
    token endpoint with the client credentials grant.

    The token is cached until shortly before it expires, so the SDK's
    validation call and its first token exchange share a single fetch.
    """

    def __init__(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        resource_id: str,
        resource_param: str = "resource",
    ):
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._client_secret = client_secret
        self._resource_id = resource_id
        self._resource_param = resource_param
        self._lock = threading.Lock()
        self._token = None
        self._expires_at = 0.0

    def id_token(self) -> IdToken:
        with self._lock:
            if self._token and time.time() < self._expires_at - _EXPIRY_SKEW_SECONDS:
                return IdToken(jwt=self._token)

            resp = requests.post(
                self._token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    self._resource_param: self._resource_id,
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
    Databricks via oidc_credentials_provider."""

    @credentials_strategy("external-client-credentials-wif", ["host"])
    def strategy(cfg):
        # oidc_credentials_provider swallows token-source errors and returns
        # None ("not configured"). Fetch once up front so a misconfigured IdP
        # surfaces its real error; the result is cached for the SDK's calls.
        id_token_source.id_token()
        return oidc_credentials_provider(cfg, id_token_source)

    return strategy


def build_workspace_client() -> WorkspaceClient:
    token_source = ClientCredentialsIdTokenSource(
        token_endpoint=_require("EXTERNAL_TOKEN_ENDPOINT"),
        client_id=_require("EXTERNAL_CLIENT_ID"),
        client_secret=_require("EXTERNAL_CLIENT_SECRET"),
        resource_id=_require("EXTERNAL_RESOURCE_ID"),
        resource_param=os.environ.get("EXTERNAL_RESOURCE_PARAM", "resource").strip() or "resource",
    )
    # client_id is the Databricks service principal for WIF. Passed explicitly
    # so it is never confused with the external EXTERNAL_CLIENT_ID.
    return WorkspaceClient(
        host=_require("DATABRICKS_HOST"),
        client_id=os.environ.get("DATABRICKS_CLIENT_ID", "").strip() or None,
        credentials_strategy=external_wif_strategy(token_source),
    )


def main():
    load_dotenv()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

    w = build_workspace_client()
    print(f"auth_type: {w.config.auth_type}")

    me = w.current_user.me()
    print(f"current user: {me.user_name} (id={me.id})")

    job_runs = w.jobs.list_runs(expand_tasks=True)

    for run in job_runs:
        # filter to SubmitRun jobs
        if run.run_type == jobs.RunType.SUBMIT_RUN:
            tasks = run.tasks

            compute_used = []
            # Iterate over tasks in the run
            for task in run.tasks:
                """
                - Tasks with All Purpose clusters will have an existing_cluster_id
                - Tasks with a Jobs cluster will have the new_cluster represented as ClusterSpec
                - SQL tasks will have a sql_warehouse_id
                """
                task_compute = (
                    {"existing_cluster_id": task.existing_cluster_id}
                    if task.existing_cluster_id
                    else (
                        {"new_cluster": task.new_cluster}
                        if task.new_cluster
                        else ({"sql_warehouse_id": task.sql_task.warehouse_id} if task.sql_task else {})
                    )
                )

                # Append the task compute info to a list for the job
                compute_used.append(task_compute)

            logging.info(f"run_id: {run.run_id}, compute_used: {compute_used}")


if __name__ == "__main__":
    main()
