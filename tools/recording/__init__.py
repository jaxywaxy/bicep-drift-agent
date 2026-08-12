"""Record and replay the real Azure payloads this pipeline reads.

Off unless explicitly switched on. When inactive every entry point here is a
comparison against `None`, so the production read path is unchanged.

## The two seams

All Azure egress leaves through exactly two places, and both are intercepted:

- **ARM REST** - `tools/http_util.urlopen_checked`, which every collector, the
  Activity Log fetch, and the deployment-stack comparator already funnel
  through. The hook lives inside that function rather than in a wrapper around
  it, because its docstring already claims to be "the single place every ARM
  REST read passes through" and a second, parallel path would make that false.
- **Azure SDK** - the shared `azure.core` transport, patched for the duration of
  a session. Resource Graph, RBAC, policy, monitor and targeting each construct
  their own client; threading a `transport=` argument through all six would add
  a seventh way to do the same thing to a codebase whose most expensive recurring
  defect is precisely that.

## Modes

    start_recording(path)  # real calls happen, responses are captured
    start_replay(path)     # no network at all, cassette answers or raises
    stop()                 # save (recording) and restore the transport

`configure_from_env()` reads `DRIFT_RECORD_CASSETTE` / `DRIFT_REPLAY_CASSETTE`
so a normal scan can be recorded without a code change. Both default to unset.

## Replay never invents an answer

A miss raises `CassetteMiss`. It does not return an empty list, an empty dict,
or a 404. This is the load-bearing decision in the whole module: in this
pipeline an empty collection means *deleted*, so a lenient replayer would
manufacture `missing_in_azure` rows for healthy resources while the suite stayed
green. Recorded non-2xx statuses are re-raised as real `urllib.error.HTTPError`s
so that callers keying on `e.code == 404` - `resource_group_exists` most
importantly - take the same branch they take against live Azure.
"""

import io
import json
import logging
import os
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

from .cassette import Cassette, CassetteMiss, Interaction

logger = logging.getLogger(__name__)

__all__ = [
    "Cassette",
    "CassetteMiss",
    "configure_from_env",
    "is_active",
    "is_recording",
    "is_replaying",
    "start_recording",
    "start_replay",
    "stop",
]

RECORD_ENV = "DRIFT_RECORD_CASSETTE"
REPLAY_ENV = "DRIFT_REPLAY_CASSETTE"

#: Hosts whose responses belong in a cassette. An allowlist rather than a
#: denylist because the artifact is committed: something new appearing in the
#: read path should default to staying out of a shared fixture, not into it.
#:
#: `urlopen_checked` is shared with the GitHub Issue publisher, which is how a
#: corpus of Azure state could otherwise end up carrying issue bodies and
#: notification content. Sovereign clouds are listed because AZURE_OPENAI_TOKEN_SCOPE
#: already exists for exactly those tenants.
_RECORDABLE_HOSTS = (
    "management.azure.com",
    "management.usgovcloudapi.net",
    "management.chinacloudapi.cn",
    "management.microsoftazure.de",
)


def _is_recordable(url: str) -> bool:
    """Whether a URL's response may be written to a cassette.

    Recording only. Replay deliberately does NOT consult this: during a replay
    every request must be answered by the cassette or raise, so a non-Azure call
    - a GitHub Issue publish, say - fails loudly instead of quietly reaching the
    real network and writing something.
    """
    host = urllib.parse.urlsplit(url).hostname or ""
    return any(host.lower() == h or host.lower().endswith("." + h)
               for h in _RECORDABLE_HOSTS)


class _Session:
    def __init__(self, mode: str, cassette: Cassette, path: Path, note: str = "") -> None:
        self.mode = mode
        self.cassette = cassette
        self.path = path
        self.note = note


#: The one live session, or None. Module-global on purpose: the seams it feeds
#: are themselves module-level functions reached from a dozen callers that have
#: no shared object to hang state off.
_session: _Session | None = None


# ---------------------------------------------------------------------------
# session control
# ---------------------------------------------------------------------------

def is_active() -> bool:
    return _session is not None


def is_recording() -> bool:
    return _session is not None and _session.mode == "record"


def is_replaying() -> bool:
    return _session is not None and _session.mode == "replay"


def start_recording(path: str | Path, note: str = "") -> None:
    """Capture every Azure read to `path`, which is written on `stop()`.

    Appends to an existing cassette rather than truncating it, so a corpus can
    be built up over several scans (one per scope, per landing zone) without
    every scan having to touch every resource type.
    """
    global _session
    path = Path(path)
    cassette = Cassette.load(path) if path.exists() else Cassette()
    cassette.metadata.setdefault("note", note)
    _session = _Session("record", cassette, path, note)
    _install_sdk_transport_hook()
    logger.info("Recording Azure payloads to %s (%d already present)", path, len(cassette))


def start_replay(path: str | Path) -> None:
    """Serve every Azure read from `path` and make no network calls."""
    global _session
    path = Path(path)
    cassette = Cassette.load(path)
    _session = _Session("replay", cassette, path)
    _install_sdk_transport_hook()
    _install_credential_hook()
    logger.info("Replaying Azure payloads from %s (%d interactions)", path, len(cassette))


def stop() -> None:
    """End the session, saving the cassette if one was being recorded."""
    global _session
    session = _session
    _session = None
    _remove_sdk_transport_hook()
    _remove_credential_hook()
    if session is not None and session.mode == "record":
        session.cassette.save(session.path)


def configure_from_env() -> bool:
    """Start a session if the environment asks for one. True if one started.

    Called once from the entry points. Recording and replay are mutually
    exclusive and setting both is a configuration error rather than a silent
    precedence rule.
    """
    record, replay = os.environ.get(RECORD_ENV), os.environ.get(REPLAY_ENV)
    if record and replay:
        raise ValueError(
            f"Set only one of {RECORD_ENV} and {REPLAY_ENV}; both are set."
        )
    if record:
        start_recording(record, note=os.environ.get("DRIFT_CASSETTE_NOTE", ""))
        return True
    if replay:
        start_replay(replay)
        return True
    return False


def current_cassette() -> Cassette | None:
    return _session.cassette if _session else None


# ---------------------------------------------------------------------------
# ARM REST seam (urllib) - called from tools/http_util.urlopen_checked
# ---------------------------------------------------------------------------

class _ReplayedResponse(io.BytesIO):
    """Stands in for an `http.client.HTTPResponse` from urllib.

    Subclasses BytesIO so `json.load(resp)` and `resp.read()` work unchanged,
    and carries the status under all three names urllib callers use in this
    codebase (`.status`, `.code`, `.getcode()`).
    """

    def __init__(self, body: bytes, status: int, url: str) -> None:
        super().__init__(body)
        self.status = status
        self.code = status
        self.url = url
        self.headers: dict[str, str] = {"Content-Type": "application/json"}

    def getcode(self) -> int:
        return self.status

    def info(self):
        return self.headers

    def __enter__(self) -> "_ReplayedResponse":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _request_parts(req: Any) -> tuple[str, str, Any]:
    """(method, url, request body) from a urllib Request or a bare URL string."""
    if isinstance(req, str):
        return "GET", req, None
    method = req.get_method() if hasattr(req, "get_method") else "GET"
    return method, req.full_url, getattr(req, "data", None)


def _as_response(interaction: Interaction, url: str) -> _ReplayedResponse:
    """Turn a recorded interaction into a live-looking response, or raise the
    error the recording captured."""
    payload = json.dumps(interaction.body if interaction.body is not None else {})
    body = payload.encode("utf-8")
    if interaction.status >= 400:
        raise urllib.error.HTTPError(
            url, interaction.status, f"replayed {interaction.status}", {}, io.BytesIO(body)
        )
    return _ReplayedResponse(body, interaction.status, url)


def replay_urlopen(req: Any) -> _ReplayedResponse:
    """The recorded answer for this request. Raises `CassetteMiss` if absent."""
    method, url, request_body = _request_parts(req)
    interaction = _session.cassette.lookup(method, url, request_body)
    return _as_response(interaction, url)


def capture_urlopen(req: Any, response: Any) -> Any:
    """Record a successful response and return one the caller can still read.

    The real response is a single-use stream, so recording it consumes it; the
    caller is handed a replayed stand-in over the same bytes. Returns the
    original untouched when not recording, which is the production path.
    """
    if not is_recording():
        return response
    method, url, request_body = _request_parts(req)
    if not _is_recordable(url):
        logger.debug("Cassette: not an Azure host, leaving %s unrecorded", url)
        return response
    raw = response.read()
    try:
        body = json.loads(raw) if raw else None
    except (ValueError, TypeError):
        logger.debug("Cassette: non-JSON response from %s, storing as text", url)
        body = raw.decode("utf-8", "replace")
    status = getattr(response, "status", None) or getattr(response, "code", 200)
    _session.cassette.record(
        method, url, status, body, request_body, note=_session.note
    )
    return _ReplayedResponse(
        raw if isinstance(raw, bytes) else json.dumps(body).encode("utf-8"), status, url
    )


def capture_http_error(req: Any, error: urllib.error.HTTPError) -> None:
    """Record a non-2xx response. No-op unless recording.

    404s in particular are load-bearing signal, not noise: `resource_group_exists`
    distinguishes a definitive 404 from an unanswerable check, and a cassette
    that dropped errors would replay that distinction as the wrong branch.
    """
    if not is_recording():
        return
    method, url, request_body = _request_parts(req)
    if not _is_recordable(url):
        return
    try:
        raw = error.read() or b"null"
        # Reading exhausted the error's stream, and this hook must be invisible
        # to the caller that is about to handle the exception. Put it back.
        error.fp = io.BytesIO(raw)
        body = json.loads(raw)
    except Exception:
        body = None
    _session.cassette.record(
        method, url, error.code, body, request_body, note=_session.note
    )


# ---------------------------------------------------------------------------
# Azure SDK seam (azure-core transport)
# ---------------------------------------------------------------------------

_original_transport_send = None
_original_get_token = None

#: Far-future expiry so no SDK pipeline decides the replayed token needs
#: refreshing mid-run and goes to AAD after all.
_REPLAY_TOKEN_EXPIRY = 4102444800  # 2100-01-01Z


def _install_credential_hook() -> None:
    """During replay, stop every credential from calling AAD.

    Intercepting the two DATA seams is not enough to take a replay offline:
    before any of them is reached, `acquire_arm_token` and ten collectors each
    construct a DefaultAzureCredential and fetch a bearer token. With no Azure
    credential - CI, or a laptop that is not logged in - that fetch fails,
    `acquire_arm_token` returns None, and the collectors record collection gaps.
    The replay would then produce a DIFFERENT result from the recording, for a
    reason having nothing to do with the payloads under test, and the fixture
    would be quietly worthless.

    The token itself is never needed: it only ever becomes an Authorization
    header, and headers are dropped rather than recorded. Replay-only - a
    recording must authenticate for real.

    Two patches, because the two seams reach a credential differently:

    - The urllib collectors call `DefaultAzureCredential.get_token` themselves.
    - The SDK clients never touch the credential directly. azure-core's
      `BearerTokenCredentialPolicy` does it for them, one policy above the
      transport - so the transport hook is never even reached when
      authentication fails. Patching the credential alone is NOT enough here,
      and looks like it is: azure-core prefers `get_token_info` when the
      credential offers it, which DefaultAzureCredential does, so a patch on
      `get_token` is silently bypassed on this path.

    The policy's on_request is neutralised rather than fed a fake token, because
    during a replay there is no outbound request left to authorise.
    """
    global _original_get_token
    if _original_get_token is not None:
        return
    try:
        from azure.core.credentials import AccessToken
        from azure.core.pipeline.policies import BearerTokenCredentialPolicy
        from azure.identity import DefaultAzureCredential
    except ImportError:  # pragma: no cover - all are declared dependencies
        return

    def replayed_token(self, *scopes, **kwargs):
        return AccessToken("replayed-token-not-a-credential", _REPLAY_TOKEN_EXPIRY)

    _original_get_token = {
        "get_token": DefaultAzureCredential.get_token,
        "get_token_info": getattr(DefaultAzureCredential, "get_token_info", None),
        "on_request": BearerTokenCredentialPolicy.on_request,
    }
    DefaultAzureCredential.get_token = replayed_token
    if _original_get_token["get_token_info"] is not None:
        DefaultAzureCredential.get_token_info = replayed_token
    BearerTokenCredentialPolicy.on_request = lambda self, request: None


def _remove_credential_hook() -> None:
    global _original_get_token
    if _original_get_token is None:
        return
    from azure.core.pipeline.policies import BearerTokenCredentialPolicy
    from azure.identity import DefaultAzureCredential

    DefaultAzureCredential.get_token = _original_get_token["get_token"]
    if _original_get_token["get_token_info"] is not None:
        DefaultAzureCredential.get_token_info = _original_get_token["get_token_info"]
    BearerTokenCredentialPolicy.on_request = _original_get_token["on_request"]
    _original_get_token = None


def _install_sdk_transport_hook() -> None:
    """Patch the shared azure-core transport for the session's duration.

    Scoped to a session and undone by `stop()`. A patch rather than a
    constructor argument because it is one seam for every SDK client, including
    ones added after this was written - a `transport=` argument only covers the
    call sites that remembered to pass it, and a collector that forgot would
    silently hit the network mid-replay.
    """
    global _original_transport_send
    if _original_transport_send is not None:
        return
    try:
        from azure.core.pipeline.transport import RequestsTransport
    except ImportError:  # pragma: no cover - azure-core is a declared dependency
        logger.warning("azure-core not importable; SDK reads will not be intercepted")
        return

    _original_transport_send = RequestsTransport.send

    def send(self, request, **kwargs):
        if is_replaying():
            return _replay_sdk(self, request)
        response = _original_transport_send(self, request, **kwargs)
        if is_recording():
            _capture_sdk(request, response)
        return response

    RequestsTransport.send = send


def _remove_sdk_transport_hook() -> None:
    global _original_transport_send
    if _original_transport_send is None:
        return
    from azure.core.pipeline.transport import RequestsTransport

    RequestsTransport.send = _original_transport_send
    _original_transport_send = None


def _sdk_request_body(request: Any) -> Any:
    body = getattr(request, "body", None) or getattr(request, "content", None)
    if isinstance(body, bytes):
        return body.decode("utf-8", "replace")
    return body


def _capture_sdk(request: Any, response: Any) -> None:
    """Record an SDK response without disturbing the caller's stream.

    Unlike urllib, azure-core has already buffered the body by the time send()
    returns, so reading it here is free of side effects.
    """
    if not _is_recordable(request.url):
        return
    try:
        raw = response.body()
        body = json.loads(raw) if raw else None
    except Exception as e:
        logger.debug("Cassette: could not capture SDK response body: %s", e)
        return
    _session.cassette.record(
        request.method,
        request.url,
        response.status_code,
        body,
        _sdk_request_body(request),
        note=_session.note,
    )


def _replay_sdk(transport: Any, request: Any) -> Any:
    """Serve an SDK request from the cassette, as a real transport response.

    Built on a synthetic `requests.Response` so the azure-core pipeline runs its
    normal deserialisation over it - the recorded bytes go through exactly the
    same model construction as live ones, which is the point.
    """
    import requests
    from azure.core.pipeline.transport import RequestsTransportResponse

    interaction = _session.cassette.lookup(
        request.method, request.url, _sdk_request_body(request)
    )
    raw = requests.Response()
    raw.status_code = interaction.status
    raw._content = json.dumps(
        interaction.body if interaction.body is not None else {}
    ).encode("utf-8")
    raw.headers["Content-Type"] = "application/json"
    raw.url = request.url
    raw.reason = "replayed"
    return RequestsTransportResponse(request, raw, transport.connection_config.data_block_size)
