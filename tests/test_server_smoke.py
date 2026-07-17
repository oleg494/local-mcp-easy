import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
TOKEN = "smoke-test-token"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url, token=None, data=None, host=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
        )
    if host is not None:
        headers["Host"] = host
    return urllib.request.Request(
        url,
        data=data,
        headers=headers,
        method="POST" if data is not None else "GET",
    )


class ServerSmokeTests(unittest.TestCase):
    def test_health_authentication_and_mcp_initialize(self):
        port = free_port()
        env = os.environ.copy()
        env.update(
            {
                "MCP_TOKEN": TOKEN,
                "MCP_BASE_DIR": str(PROJECT),
                "MCP_PORT": str(port),
                "MCP_ALLOW_COMMANDS": "0",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        process = subprocess.Popen(
            [sys.executable, str(PROJECT / "server.py")],
            cwd=str(PROJECT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            health_url = f"http://127.0.0.1:{port}/health"
            deadline = time.time() + 15
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(
                        request(health_url, TOKEN), timeout=1
                    ) as response:
                        self.assertEqual(json.loads(response.read()), {"status": "ok"})
                        break
                except (OSError, urllib.error.URLError):
                    if process.poll() is not None:
                        self.fail(f"Server exited with code {process.returncode}")
                    time.sleep(0.2)
            else:
                self.fail("Server did not become ready")

            for bad_token in (None, "wrong-token"):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(
                        request(health_url, bad_token), timeout=2
                    )
                self.assertEqual(caught.exception.code, 401)

            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(
                    request(f"http://127.0.0.1:{port}/mcp"), timeout=2
                )
            self.assertEqual(caught.exception.code, 401)

            initialize = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "smoke-test", "version": "1"},
                    },
                }
            ).encode()
            external_request = request(
                f"http://127.0.0.1:{port}/mcp",
                TOKEN,
                initialize,
                "random.serveousercontent.com",
            )
            with urllib.request.urlopen(external_request, timeout=3) as response:
                self.assertEqual(response.status, 200)

            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(
                    request(health_url, TOKEN, host="evil.example.com"), timeout=2
                )
            self.assertEqual(caught.exception.code, 403)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
