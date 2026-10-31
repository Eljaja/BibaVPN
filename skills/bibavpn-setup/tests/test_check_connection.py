import os
import socket
import subprocess
import threading
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'check-connection.sh'


class SocksServer:
    def __init__(self, status):
        self.server = socket.socket()
        self.server.bind(('127.0.0.1', 0))
        self.server.listen(1)
        self.server.settimeout(5)
        self.port = self.server.getsockname()[1]
        self.status = status
        self.host = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @staticmethod
    def recv_exact(conn, n):
        result = b''
        while len(result) < n:
            part = conn.recv(n - len(result))
            if not part:
                raise EOFError()
            result += part
        return result

    def run(self):
        try:
            conn, _ = self.server.accept()
            with conn:
                conn.settimeout(5)
                version, count = self.recv_exact(conn, 2)
                assert version == 5
                self.recv_exact(conn, count)
                conn.sendall(b'\x05\x00')
                version, command, _, address_type = self.recv_exact(conn, 4)
                assert (version, command, address_type) == (5, 1, 3)
                length = self.recv_exact(conn, 1)[0]
                self.host = self.recv_exact(conn, length).decode()
                self.recv_exact(conn, 2)
                conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                request = b''
                while b'\r\n\r\n' not in request:
                    request += conn.recv(4096)
                conn.sendall(f'HTTP/1.1 {self.status}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody'.encode())
        finally:
            self.server.close()


class CheckConnectionTests(unittest.TestCase):
    def call(self, *args):
        env = os.environ.copy()
        env['NO_PROXY'] = '*'
        env['no_proxy'] = '*'
        return subprocess.run(['bash', str(SCRIPT), *args], text=True, capture_output=True, env=env, timeout=20)

    def test_success_uses_socks_and_remote_dns_even_with_no_proxy(self):
        server = SocksServer('200 OK')
        result = self.call('--socks', f'127.0.0.1:{server.port}', '--url', 'http://target.invalid/private?token=SECRET')
        server.thread.join(5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(server.host, 'target.invalid')
        self.assertIn('200', result.stdout)
        self.assertNotIn('SECRET', result.stdout + result.stderr)
        self.assertNotIn('body', result.stdout + result.stderr)

    def test_http_failure_is_not_success(self):
        server = SocksServer('503 Service Unavailable')
        result = self.call('--socks', f'127.0.0.1:{server.port}', '--url', 'http://target.invalid/')
        server.thread.join(5)
        self.assertEqual(server.host, 'target.invalid')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('curl exit 22', result.stderr)

    def test_invalid_arguments_and_credentials_rejected(self):
        for args in [(), ('--url', 'file:///etc/passwd'), ('--url', 'https://user:SECRET@example.com/'), ('--socks', 'user:pass@host:1080', '--url', 'http://example.com/')]:
            with self.subTest(args=args):
                result = self.call(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('SECRET', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
