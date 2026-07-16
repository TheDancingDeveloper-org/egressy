import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from external_probe_service import (
    ExternalProbeService,
    ProbeRequest,
    Settings,
    evaluate_request,
    is_disallowed_source_ip,
    parse_probe_request,
)


def test_settings() -> Settings:
    return Settings(
        listen_host="0.0.0.0",
        listen_port=443,
        token="secret-token",
        cert_path=None,
        key_path=None,
        freshness_seconds=60,
        connect_timeout_seconds=1.0,
        rate_limit_requests=100,
        rate_limit_window_seconds=60,
        body_limit_bytes=4096,
        trusted_proxy_cidrs=("127.0.0.0/8", "::1/128"),
    )


class ParsingTests(unittest.TestCase):
    def test_parse_probe_request_accepts_expected_shape(self) -> None:
        request = parse_probe_request(
            {
                "instance_id": "example-gateway",
                "request_id": "abc",
                "timestamp_unix_ms": 1000,
                "claimed_public_ip": "8.8.8.8",
                "forwarded_port": 443,
            }
        )
        self.assertEqual(request.instance_id, "example-gateway")
        self.assertEqual(request.claimed_public_ip, "8.8.8.8")
        self.assertEqual(request.forwarded_port, 443)

    def test_parse_probe_request_rejects_private_claimed_ip(self) -> None:
        with self.assertRaises(ValueError):
            parse_probe_request(
                {
                    "instance_id": "example-gateway",
                    "request_id": "abc",
                    "timestamp_unix_ms": 1000,
                    "claimed_public_ip": "192.168.1.10",
                }
            )

    def test_parse_probe_request_rejects_non_object_json(self) -> None:
        with self.assertRaises(ValueError):
            parse_probe_request([])


class EvaluationTests(unittest.TestCase):
    def test_non_public_source_is_rejected(self) -> None:
        response = evaluate_request(
            request=ProbeRequest(
                instance_id="example-gateway",
                request_id="abc",
                timestamp_unix_ms=1000,
                claimed_public_ip="8.8.8.8",
                forwarded_port=None,
            ),
            source_ip="100.92.4.57",
            now_ms=1000,
            freshness_seconds=60,
            connect_timeout_seconds=1.0,
            tcp_connector=lambda *_: True,
        )
        self.assertEqual(response.reason_code, "external_probe.non_public_source")
        self.assertFalse(response.source_public_non_tailscale)

    def test_claimed_ip_mismatch_is_reported(self) -> None:
        response = evaluate_request(
            request=ProbeRequest(
                instance_id="example-gateway",
                request_id="abc",
                timestamp_unix_ms=1000,
                claimed_public_ip="1.1.1.1",
                forwarded_port=None,
            ),
            source_ip="8.8.8.8",
            now_ms=1000,
            freshness_seconds=60,
            connect_timeout_seconds=1.0,
            tcp_connector=lambda *_: True,
        )
        self.assertEqual(response.reason_code, "external_probe.claimed_ip_mismatch")
        self.assertFalse(response.source_matches_claimed_ip)

    def test_unreachable_forwarded_port_is_reported(self) -> None:
        response = evaluate_request(
            request=ProbeRequest(
                instance_id="example-gateway",
                request_id="abc",
                timestamp_unix_ms=1000,
                claimed_public_ip="8.8.8.8",
                forwarded_port=443,
            ),
            source_ip="8.8.8.8",
            now_ms=1000,
            freshness_seconds=60,
            connect_timeout_seconds=1.0,
            tcp_connector=lambda *_: False,
        )
        self.assertEqual(response.reason_code, "external_probe.port_unreachable")
        self.assertFalse(response.tcp_port_reachable)

    def test_stale_timestamp_reports_invalid_request_with_null_checks(self) -> None:
        # Contract pin: egressy-probe maps this exact shape (non-healthy
        # reason, null check results) to "unavailable". If this response
        # changes, update map_external_response in egressy-probe.rs too.
        response = evaluate_request(
            request=ProbeRequest(
                instance_id="example-gateway",
                request_id="abc",
                timestamp_unix_ms=1000,
                claimed_public_ip="8.8.8.8",
                forwarded_port=443,
            ),
            source_ip="8.8.8.8",
            now_ms=1000 + 61_000,
            freshness_seconds=60,
            connect_timeout_seconds=1.0,
            tcp_connector=lambda *_: True,
        )
        self.assertEqual(response.reason_code, "external_probe.invalid_request")
        self.assertTrue(response.source_public_non_tailscale)
        self.assertIsNone(response.source_matches_claimed_ip)
        self.assertIsNone(response.tcp_port_reachable)

    def test_healthy_request_returns_safe_success(self) -> None:
        response = evaluate_request(
            request=ProbeRequest(
                instance_id="example-gateway",
                request_id="abc",
                timestamp_unix_ms=1000,
                claimed_public_ip="8.8.8.8",
                forwarded_port=443,
            ),
            source_ip="8.8.8.8",
            now_ms=1000,
            freshness_seconds=60,
            connect_timeout_seconds=1.0,
            tcp_connector=lambda *_: True,
        )
        self.assertEqual(response.reason_code, "external_probe.healthy")
        self.assertTrue(response.source_public_non_tailscale)
        self.assertTrue(response.tcp_port_reachable)
        payload = response.to_json()
        self.assertNotIn("forwarded_port", payload)
        self.assertNotIn("claimed_public_ip", payload)
        self.assertNotIn("request_id", payload)


class ServiceTests(unittest.TestCase):
    def test_bearer_token_auth_failure(self) -> None:
        service = ExternalProbeService(test_settings())
        status, payload = service.handle_request(
            source_ip="8.8.8.8",
            authorization="Bearer wrong",
            body=b"{}",
        )
        self.assertEqual(status, 401)
        self.assertEqual(payload["reason_code"], "external_probe.auth_failed")

    def test_request_success_path(self) -> None:
        service = ExternalProbeService(
            test_settings(),
            tcp_connector=lambda *_: True,
            now_ms=lambda: 1000,
        )
        status, payload = service.handle_request(
            source_ip="8.8.8.8",
            authorization="Bearer secret-token",
            body=(
                b'{"instance_id":"example-gateway","request_id":"abc",'
                b'"timestamp_unix_ms":1000,"claimed_public_ip":"8.8.8.8",'
                b'"forwarded_port":443}'
            ),
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["reason_code"], "external_probe.healthy")
        self.assertTrue(payload["source_public_non_tailscale"])

    def test_replayed_request_is_rejected(self) -> None:
        service = ExternalProbeService(test_settings(), now_ms=lambda: 1000)
        body = b'{"instance_id":"example-gateway","request_id":"abc","timestamp_unix_ms":1000}'
        first, _ = service.handle_request(
            source_ip="8.8.8.8",
            authorization="Bearer secret-token",
            body=body,
        )
        second, payload = service.handle_request(
            source_ip="8.8.8.8",
            authorization="Bearer secret-token",
            body=body,
        )
        self.assertEqual(first, 200)
        self.assertEqual(second, 409)
        self.assertEqual(payload["reason_code"], "external_probe.replayed_request")

    def test_trusted_loopback_proxy_supplies_public_source(self) -> None:
        service = ExternalProbeService(test_settings())
        self.assertEqual(
            service.source_ip("127.0.0.1", "192.0.2.1, 8.8.8.8"), "8.8.8.8"
        )

    def test_untrusted_peer_cannot_spoof_forwarded_source(self) -> None:
        service = ExternalProbeService(test_settings())
        self.assertEqual(service.source_ip("1.1.1.1", "8.8.8.8"), "1.1.1.1")


class IpClassificationTests(unittest.TestCase):
    def test_disallowed_ranges_cover_tailscale_and_private(self) -> None:
        import ipaddress

        self.assertTrue(is_disallowed_source_ip(ipaddress.ip_address("100.92.4.57")))
        self.assertTrue(is_disallowed_source_ip(ipaddress.ip_address("192.168.1.1")))
        self.assertFalse(is_disallowed_source_ip(ipaddress.ip_address("8.8.8.8")))


if __name__ == "__main__":
    unittest.main()
