#!/usr/bin/env python3
"""Reference external validation service for Egressy."""

from __future__ import annotations

import ipaddress
import hmac
import json
import os
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Optional


BODY_LIMIT_BYTES = 4096
DEFAULT_FRESHNESS_SECONDS = 60
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_RATE_LIMIT_REQUESTS = 30
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60
CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class Settings:
    listen_host: str
    listen_port: int
    token: str
    cert_path: Optional[str]
    key_path: Optional[str]
    freshness_seconds: int
    connect_timeout_seconds: float
    rate_limit_requests: int
    rate_limit_window_seconds: int
    body_limit_bytes: int
    trusted_proxy_cidrs: tuple[str, ...]

    @classmethod
    def from_env(cls) -> "Settings":
        token = os.getenv("EXTERNAL_PROBE_TOKEN") or _read_optional_file(
            os.getenv("EXTERNAL_PROBE_TOKEN_FILE")
        )
        if not token:
            raise ValueError(
                "EXTERNAL_PROBE_TOKEN or EXTERNAL_PROBE_TOKEN_FILE is required"
            )

        cert_path = os.getenv("EXTERNAL_PROBE_TLS_CERT")
        key_path = os.getenv("EXTERNAL_PROBE_TLS_KEY")
        if bool(cert_path) != bool(key_path):
            raise ValueError(
                "EXTERNAL_PROBE_TLS_CERT and EXTERNAL_PROBE_TLS_KEY must be set together"
            )

        return cls(
            listen_host=os.getenv("EXTERNAL_PROBE_LISTEN_HOST", "0.0.0.0"),
            listen_port=int(os.getenv("EXTERNAL_PROBE_LISTEN_PORT", "443")),
            token=token.strip(),
            cert_path=cert_path,
            key_path=key_path,
            freshness_seconds=int(
                os.getenv(
                    "EXTERNAL_PROBE_FRESHNESS_SECONDS",
                    str(DEFAULT_FRESHNESS_SECONDS),
                )
            ),
            connect_timeout_seconds=float(
                os.getenv(
                    "EXTERNAL_PROBE_CONNECT_TIMEOUT_SECONDS",
                    str(DEFAULT_CONNECT_TIMEOUT_SECONDS),
                )
            ),
            rate_limit_requests=int(
                os.getenv(
                    "EXTERNAL_PROBE_RATE_LIMIT_REQUESTS",
                    str(DEFAULT_RATE_LIMIT_REQUESTS),
                )
            ),
            rate_limit_window_seconds=int(
                os.getenv(
                    "EXTERNAL_PROBE_RATE_LIMIT_WINDOW_SECONDS",
                    str(DEFAULT_RATE_LIMIT_WINDOW_SECONDS),
                )
            ),
            body_limit_bytes=int(
                os.getenv("EXTERNAL_PROBE_BODY_LIMIT_BYTES", str(BODY_LIMIT_BYTES))
            ),
            trusted_proxy_cidrs=tuple(
                item.strip()
                for item in os.getenv(
                    "EXTERNAL_PROBE_TRUSTED_PROXY_CIDRS", "127.0.0.0/8,::1/128"
                ).split(",")
                if item.strip()
            ),
        )


@dataclass(frozen=True)
class ProbeRequest:
    instance_id: str
    request_id: str
    timestamp_unix_ms: int
    claimed_public_ip: Optional[str]
    forwarded_port: Optional[int]


@dataclass(frozen=True)
class ProbeResponse:
    observed_at_unix_ms: int
    source_public_non_tailscale: bool
    source_matches_claimed_ip: Optional[bool]
    tcp_port_reachable: Optional[bool]
    reason_code: str
    safe_message: str

    def to_json(self) -> dict[str, object]:
        return {
            "observed_at_unix_ms": self.observed_at_unix_ms,
            "source_public_non_tailscale": self.source_public_non_tailscale,
            "source_matches_claimed_ip": self.source_matches_claimed_ip,
            "tcp_port_reachable": self.tcp_port_reachable,
            "reason_code": self.reason_code,
            "safe_message": self.safe_message,
        }


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, client_ip: str, now: float) -> bool:
        with self._lock:
            bucket = self._requests[client_ip]
            cutoff = now - self._window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._max_requests:
                return False
            bucket.append(now)
            return True


class ExternalProbeService:
    def __init__(
        self,
        settings: Settings,
        *,
        tcp_connector: Optional[Callable[[str, int, float], bool]] = None,
        now_ms: Optional[Callable[[], int]] = None,
    ) -> None:
        self.settings = settings
        self._tcp_connector = tcp_connector or tcp_connect
        self._now_ms = now_ms or current_time_ms
        self._rate_limiter = RateLimiter(
            settings.rate_limit_requests,
            settings.rate_limit_window_seconds,
        )
        self._trusted_proxies = tuple(
            ipaddress.ip_network(cidr) for cidr in settings.trusted_proxy_cidrs
        )
        self._seen_requests: dict[str, int] = {}
        self._seen_requests_lock = threading.Lock()

    def check_authorization(self, header_value: Optional[str]) -> bool:
        if not header_value:
            return False
        expected = f"Bearer {self.settings.token}"
        return hmac.compare_digest(header_value, expected)

    def source_ip(self, peer_ip: str, forwarded_for: Optional[str]) -> str:
        peer = ipaddress.ip_address(peer_ip)
        if not any(peer in network for network in self._trusted_proxies):
            return peer_ip
        if not forwarded_for:
            raise ValueError("trusted reverse proxy did not provide a client address")
        source = forwarded_for.split(",")[-1].strip()
        return str(ipaddress.ip_address(source))

    def claim_request_id(self, request_id: str, now_ms: int) -> bool:
        cutoff = now_ms - (self.settings.freshness_seconds * 1000)
        with self._seen_requests_lock:
            self._seen_requests = {
                key: observed
                for key, observed in self._seen_requests.items()
                if observed >= cutoff
            }
            if request_id in self._seen_requests:
                return False
            self._seen_requests[request_id] = now_ms
            return True

    def handle_request(
        self,
        *,
        source_ip: str,
        authorization: Optional[str],
        body: bytes,
    ) -> tuple[int, dict[str, object]]:
        if not self.check_authorization(authorization):
            return self._error(
                HTTPStatus.UNAUTHORIZED,
                "external_probe.auth_failed",
                "The external probe request was not authorized.",
            )

        now = time.time()
        if not self._rate_limiter.allow(source_ip, now):
            return self._error(
                HTTPStatus.TOO_MANY_REQUESTS,
                "external_probe.rate_limited",
                "The external probe request rate limit was exceeded.",
            )

        if len(body) > self.settings.body_limit_bytes:
            return self._error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "external_probe.invalid_request",
                "The external probe request body was too large.",
            )

        try:
            payload = json.loads(body.decode("utf-8"))
            request = parse_probe_request(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return self._error(
                HTTPStatus.BAD_REQUEST,
                "external_probe.invalid_request",
                "The external probe request was invalid.",
            )

        now_ms = self._now_ms()
        if abs(now_ms - request.timestamp_unix_ms) <= self.settings.freshness_seconds * 1000:
            if not self.claim_request_id(request.request_id, now_ms):
                return self._error(
                    HTTPStatus.CONFLICT,
                    "external_probe.replayed_request",
                    "The external probe request was already processed.",
                )

        response = evaluate_request(
            request=request,
            source_ip=source_ip,
            now_ms=now_ms,
            freshness_seconds=self.settings.freshness_seconds,
            connect_timeout_seconds=self.settings.connect_timeout_seconds,
            tcp_connector=self._tcp_connector,
        )
        return HTTPStatus.OK, response.to_json()

    def _error(
        self, status: HTTPStatus, reason_code: str, safe_message: str
    ) -> tuple[int, dict[str, object]]:
        return (
            int(status),
            {
                "reason_code": reason_code,
                "safe_message": safe_message,
            },
        )


def parse_probe_request(payload: object) -> ProbeRequest:
    if not isinstance(payload, dict):
        raise ValueError("request body must be a JSON object")
    instance_id = _require_non_empty_string(payload.get("instance_id"), "instance_id")
    request_id = _require_non_empty_string(payload.get("request_id"), "request_id")
    timestamp_unix_ms = _require_int(payload.get("timestamp_unix_ms"), "timestamp_unix_ms")
    claimed_public_ip = payload.get("claimed_public_ip")
    if claimed_public_ip is not None:
        claimed_public_ip = _require_ip_string(claimed_public_ip, "claimed_public_ip")
    forwarded_port = payload.get("forwarded_port")
    if forwarded_port is not None:
        forwarded_port = _require_port(forwarded_port, "forwarded_port")
    return ProbeRequest(
        instance_id=instance_id,
        request_id=request_id,
        timestamp_unix_ms=timestamp_unix_ms,
        claimed_public_ip=claimed_public_ip,
        forwarded_port=forwarded_port,
    )


def evaluate_request(
    *,
    request: ProbeRequest,
    source_ip: str,
    now_ms: int,
    freshness_seconds: int,
    connect_timeout_seconds: float,
    tcp_connector: Callable[[str, int, float], bool],
) -> ProbeResponse:
    observed_at_unix_ms = now_ms
    source_addr = ipaddress.ip_address(source_ip)
    source_public_non_tailscale = not is_disallowed_source_ip(source_addr)

    if abs(now_ms - request.timestamp_unix_ms) > freshness_seconds * 1000:
        return ProbeResponse(
            observed_at_unix_ms=observed_at_unix_ms,
            source_public_non_tailscale=source_public_non_tailscale,
            source_matches_claimed_ip=None,
            tcp_port_reachable=None,
            reason_code="external_probe.invalid_request",
            safe_message="The external probe request timestamp was outside the allowed window.",
        )

    source_matches_claimed_ip: Optional[bool] = None
    if request.claimed_public_ip is not None:
        source_matches_claimed_ip = source_ip == request.claimed_public_ip

    if not source_public_non_tailscale:
        return ProbeResponse(
            observed_at_unix_ms=observed_at_unix_ms,
            source_public_non_tailscale=False,
            source_matches_claimed_ip=source_matches_claimed_ip,
            tcp_port_reachable=None,
            reason_code="external_probe.non_public_source",
            safe_message="The observed source address was not public and non-Tailscale.",
        )

    if source_matches_claimed_ip is False:
        return ProbeResponse(
            observed_at_unix_ms=observed_at_unix_ms,
            source_public_non_tailscale=True,
            source_matches_claimed_ip=False,
            tcp_port_reachable=None,
            reason_code="external_probe.claimed_ip_mismatch",
            safe_message="The observed source address did not match the claimed public address.",
        )

    tcp_port_reachable: Optional[bool] = None
    if request.forwarded_port is not None:
        if request.claimed_public_ip is None:
            return ProbeResponse(
                observed_at_unix_ms=observed_at_unix_ms,
                source_public_non_tailscale=True,
                source_matches_claimed_ip=None,
                tcp_port_reachable=None,
                reason_code="external_probe.invalid_request",
                safe_message="A forwarded port was provided without a claimed public address.",
            )
        tcp_port_reachable = tcp_connector(
            request.claimed_public_ip,
            request.forwarded_port,
            connect_timeout_seconds,
        )
        if not tcp_port_reachable:
            return ProbeResponse(
                observed_at_unix_ms=observed_at_unix_ms,
                source_public_non_tailscale=True,
                source_matches_claimed_ip=source_matches_claimed_ip,
                tcp_port_reachable=False,
                reason_code="external_probe.port_unreachable",
                safe_message="The claimed forwarded TCP port was not externally reachable.",
            )

    return ProbeResponse(
        observed_at_unix_ms=observed_at_unix_ms,
        source_public_non_tailscale=True,
        source_matches_claimed_ip=source_matches_claimed_ip,
        tcp_port_reachable=tcp_port_reachable,
        reason_code="external_probe.healthy",
        safe_message="Public HTTPS path succeeded and the source was public and non-Tailscale.",
    )


def is_disallowed_source_ip(address: ipaddress._BaseAddress) -> bool:
    if address.version == 4:
        return (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address in CGNAT_V4
        )
    return (
        address.is_loopback
        or address.is_multicast
        or address.is_unspecified
        or address.is_private
        or getattr(address, "is_link_local", False)
    )


def tcp_connect(host: str, port: int, timeout_seconds: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "egressy-edgeprobe/1.0"

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/v1/check":
            self.send_error(HTTPStatus.NOT_FOUND)
            return

        content_length_header = self.headers.get("Content-Length")
        try:
            content_length = int(content_length_header or "0")
        except ValueError:
            content_length = 0

        if (
            content_length < 0
            or content_length > self.server.service.settings.body_limit_bytes
        ):
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "reason_code": "external_probe.invalid_request",
                    "safe_message": "The external probe request body was too large.",
                },
            )
            return

        body = self.rfile.read(content_length)
        try:
            source_ip = self.server.service.source_ip(
                self.client_address[0], self.headers.get("X-Forwarded-For")
            )
        except ValueError:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "reason_code": "external_probe.invalid_source",
                    "safe_message": "The external probe source address was invalid.",
                },
            )
            return

        status, payload = self.server.service.handle_request(
            source_ip=source_ip,
            authorization=self.headers.get("Authorization"),
            body=body,
        )
        self._send_json(status, payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/livez":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


class ProbeHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], service: ExternalProbeService):
        super().__init__(server_address, RequestHandler)
        self.service = service


def make_server(settings: Settings) -> ProbeHTTPServer:
    service = ExternalProbeService(settings)
    server = ProbeHTTPServer((settings.listen_host, settings.listen_port), service)
    if settings.cert_path and settings.key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(settings.cert_path, settings.key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def current_time_ms() -> int:
    return int(time.time() * 1000)


def _read_optional_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def _require_non_empty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


def _require_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    return value


def _require_ip_string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    address = ipaddress.ip_address(value)
    if is_disallowed_source_ip(address):
        raise ValueError(f"{field} must be public and non-Tailscale")
    return value


def _require_port(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 65535:
        raise ValueError(f"{field} must be an integer between 1 and 65535")
    return value


def main() -> None:
    settings = Settings.from_env()
    server = make_server(settings)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
