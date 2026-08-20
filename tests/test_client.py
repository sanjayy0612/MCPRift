from __future__ import annotations

import asyncio
import http.server
import socket
import subprocess
import sys
import threading
import time
import unittest

from mcprift.client import ConnectionFailure, connect, validate_controlled_url


class ClientTests(unittest.TestCase):
    def test_rejects_non_loopback_and_credential_bearing_urls(self) -> None:
        for url in (
            "https://controlled.example/mcp",
            "http://user:secret@127.0.0.1:8080/mcp",
            "http://127.0.0.1:8080/mcp?access_token=secret",
        ):
            with self.assertRaises(ConnectionFailure) as raised:
                validate_controlled_url(url)
            self.assertNotIn("secret", str(raised.exception))
            self.assertNotIn("controlled.example", str(raised.exception))

    def test_failure_does_not_leak_the_target(self) -> None:
        class SecretResponseHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self._send_secret()

            def do_POST(self) -> None:
                self._send_secret()

            def _send_secret(self) -> None:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"authorization token: secret-value")

            def log_message(self, format: str, *args: object) -> None:
                pass

        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), SecretResponseHandler
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        target = f"http://127.0.0.1:{server.server_port}/mcp"
        try:
            with self.assertRaises(ConnectionFailure) as raised:
                asyncio.run(connect(target))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertNotIn(target, str(raised.exception))
        self.assertNotIn("secret-value", str(raised.exception))

    def test_does_not_follow_target_redirects(self) -> None:
        redirected_requests = 0

        class RedirectedHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                nonlocal redirected_requests
                redirected_requests += 1

            def log_message(self, format: str, *args: object) -> None:
                pass

        redirected = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), RedirectedHandler
        )
        redirected_thread = threading.Thread(target=redirected.serve_forever)
        redirected_thread.start()

        location = f"http://127.0.0.1:{redirected.server_port}/mcp"

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(307)
                self.send_header("Location", location)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                pass

        redirector = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirector_thread = threading.Thread(target=redirector.serve_forever)
        redirector_thread.start()
        try:
            with self.assertRaises(ConnectionFailure):
                asyncio.run(connect(f"http://127.0.0.1:{redirector.server_port}/mcp"))
        finally:
            redirector.shutdown()
            redirector.server_close()
            redirector_thread.join(timeout=5)
            redirected.shutdown()
            redirected.server_close()
            redirected_thread.join(timeout=5)

        self.assertEqual(redirected_requests, 0)

    def test_connects_to_the_sdk_fixture(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]

        fixture = subprocess.Popen(
            [sys.executable, "-m", "mcprift.fixture", "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            self._wait_until_listening(port, fixture)
            result = asyncio.run(connect(f"http://127.0.0.1:{port}/mcp"))
        finally:
            fixture.terminate()
            fixture.wait(timeout=5)

        self.assertEqual(result.server_name, "phase-1-fixture")
        self.assertEqual(result.server_version, "0.0.1")
        self.assertTrue(result.protocol_version)
        self.assertEqual(result.transport, "streamable-http")

    def _wait_until_listening(
        self, port: int, fixture: subprocess.Popen[bytes]
    ) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if fixture.poll() is not None:
                self.fail("fixture exited before accepting connections")
            with socket.socket() as client:
                if client.connect_ex(("127.0.0.1", port)) == 0:
                    return
            time.sleep(0.05)
        self.fail("fixture did not start within 10 seconds")
