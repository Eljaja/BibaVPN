#!/usr/bin/env python3
"""Finite direct HTTPS vs BibaVPN SOCKS/WSS benchmark (Docker, curl, openssl).

Build release binaries first, or pass --client/--server to compare saved builds.
The origin's .invalid hostname exists only on an isolated Docker network; SOCKS
must resolve it server-side. Every run includes a server-stop negative control.
JSON Lines output measures full transfers, including connection setup.
For a host packet filter that stalls large local transfers, --origin-mss 1200
sets TCP_MAXSEG only on the temporary origin listener; the chosen value is logged. No public
DNS, external downloads, host routing changes, or privileged containers are used.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time


ORIGIN = r'''
import http.server
import ssl
import socket
import sys
SIZE = int(sys.argv[1])
BLOCK = bytes(1024 * 1024)
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_GET(self):
        n = SIZE if self.path == '/payload' else 1
        self.send_response(200)
        self.send_header('Content-Length', str(n))
        self.send_header('Connection', 'close')
        self.end_headers()
        try:
            while n:
                chunk = BLOCK[:min(n, len(BLOCK))]
                self.wfile.write(chunk)
                n -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
server = http.server.ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
# Optional fixture-only workaround for local packet filters, never host configuration.
if int(sys.argv[2]):
    server.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, int(sys.argv[2]))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/lab/cert.pem', '/lab/key.pem')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
'''


def run(args, timeout=30, check=True):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f'{Path(args[0]).name} exceeded {timeout}s deadline') from exc
    if check and result.returncode:
        # Commands may contain freshly generated tunnel credentials: never echo argv.
        raise RuntimeError(f'{Path(args[0]).name} failed ({result.returncode}): '
                           f'{result.stderr.strip()[-2000:]}')
    return result


def docker(*args, **kwargs):
    return run(['docker', *args], **kwargs).stdout.strip()


def emit(**values):
    print(json.dumps(values), flush=True)


def curl_result(args, timeout):
    result = run(['curl', '--silent', '--show-error', '--fail', '--connect-timeout', '5',
                  '--max-time', str(timeout), '--output', os.devnull,
                  '--write-out', '%{json}', *args], timeout=timeout + 3, check=False)
    try:
        data = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f'curl did not return transfer metrics: {result.stderr}') from exc
    return result, data


def validate_transfer(result, data, expected):
    if (result.returncode or data.get('http_code') != 200
            or data.get('size_download') != expected or data.get('time_total', 0) <= 0):
        raise RuntimeError(f'incomplete transfer: rc={result.returncode}, '
                           f'HTTP={data.get("http_code")}, bytes={data.get("size_download")}, '
                           f'expected={expected}; {result.stderr.strip()}')


def positive(value):
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError('must be positive')
    return n


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, help='saved bibavpn-client binary')
    parser.add_argument('--server', type=Path, help='saved bibavpn-server binary')
    parser.add_argument('--bytes', type=positive, default=64 * 1024 * 1024)
    parser.add_argument('--repeats', type=positive, default=3)
    parser.add_argument('--timeout', type=positive, default=60, help='seconds per transfer')
    parser.add_argument('--label', default='local')
    parser.add_argument('--origin-mss', type=positive, default=0, help='optional origin-listener TCP_MAXSEG, e.g. 1200 for local packet filters; default unchanged')
    parser.add_argument('--image', default='python:3.12-slim', help='cached Docker image with Python and compatible glibc')
    parser.add_argument('--client-arg', action='append', default=[], help='extra client argument; repeat, e.g. --client-arg=--max-pad --client-arg=0')
    args = parser.parse_args()
    for executable in ('docker', 'curl', 'openssl'):
        if not shutil.which(executable):
            raise RuntimeError(f'missing prerequisite: {executable}')
    docker('info', '--format', '{{.ServerVersion}}')
    if run(['docker', 'image', 'inspect', args.image], check=False).returncode:
        raise RuntimeError(f'Docker image is not cached; run docker pull {args.image} first')
    if args.client is None or args.server is None:
        repo = Path(__file__).resolve().parent.parent
        metadata = json.loads(run(['cargo', 'metadata', '--no-deps', '--format-version', '1',
                                   '--manifest-path', str(repo / 'Cargo.toml')]).stdout)
        target = Path(metadata['target_directory']) / 'release'
        args.client = args.client or target / 'bibavpn-client'
        args.server = args.server or target / 'bibavpn-server'
    args.client, args.server = args.client.resolve(), args.server.resolve()
    for binary in (args.client, args.server):
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise RuntimeError(f'missing executable {binary}; run cargo build --release -p bibavpn first')

    tag = 'biba-bench-' + secrets.token_hex(6)
    origin, server = tag + '-origin', tag + '-server'
    child = None
    owned_containers = []
    owned_network = False
    # Avoid application proxy environment affecting readiness or direct measurements.
    with tempfile.TemporaryDirectory(prefix=tag) as tmp:
        lab = Path(tmp)
        try:
            run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                 '-keyout', str(lab / 'key.pem'), '-out', str(lab / 'cert.pem'),
                 '-subj', '/CN=biba-bench.invalid', '-addext', 'subjectAltName=DNS:biba-bench.invalid'])
            (lab / 'origin.py').write_text(ORIGIN)
            docker('network', 'create', tag)
            owned_network = True
            # Register names before creation so a timed-out docker invocation is cleaned up too.
            owned_containers.append(origin)
            docker('run', '--rm', '-d', '--name', origin, '--network', tag,
                   '--network-alias', 'biba-bench.invalid', '-p', '127.0.0.1::8080',
                   '-v', f'{lab}:/lab:ro', args.image, 'python', '/lab/origin.py', str(args.bytes), str(args.origin_mss))
            token, psk = secrets.token_hex(24), secrets.token_hex(24)
            owned_containers.append(server)
            docker('run', '--rm', '-d', '--name', server, '--network', tag,
                   '-p', '127.0.0.1::8443', '-v', f'{lab}:/lab:ro',
                   '-v', f'{args.server}:/server:ro', args.image, '/server',
                   '--listen', '0.0.0.0:8443', '--cert', '/lab/cert.pem', '--key', '/lab/key.pem',
                   '--token', token, '--psk', psk, '--proto-domain', 'bench', '--log-level', 'error')
            origin_port = int(docker('port', origin, '8080/tcp').rsplit(':', 1)[1])
            server_port = int(docker('port', server, '8443/tcp').rsplit(':', 1)[1])
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                socks_port = probe.getsockname()[1]
            with (lab / 'client.log').open('w') as client_log:
                child = subprocess.Popen([str(args.client), '--server', f'127.0.0.1:{server_port}',
                    '--sni', 'biba-bench.invalid', '--pin-cert', str(lab / 'cert.pem'),
                    '--token', token, '--psk', psk, '--proto-domain', 'bench',
                    '--socks5', f'127.0.0.1:{socks_port}', '--log-level', 'error', *args.client_arg],
                    stdout=client_log, stderr=client_log)
            deadline = time.monotonic() + 15
            while True:
                if child.poll() is not None:
                    raise RuntimeError('client exited before readiness: ' + (lab / 'client.log').read_text()[-2000:])
                try:
                    with socket.create_connection(('127.0.0.1', socks_port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('client SOCKS listener did not become ready')
                    time.sleep(.1)
            common = ['--cacert', str(lab / 'cert.pem')]
            direct = common + ['--noproxy', '*', '--connect-to',
                f'biba-bench.invalid:{origin_port}:127.0.0.1:{origin_port}']
            mux = common + ['--noproxy', '', '--socks5-hostname', f'127.0.0.1:{socks_port}']
            routes = [('direct', direct, f'https://biba-bench.invalid:{origin_port}'),
                      ('mux', mux, 'https://biba-bench.invalid:8080')]
            # Actual HTTPS requests prove both origin and tunnel readiness before timing.
            for _, options, url in routes:
                result, data = curl_result(options + [url + '/ready'], 15)
                validate_transfer(result, data, 1)
            emit(event='setup', label=args.label, client=str(args.client), server=str(args.server),
                 bytes=args.bytes, repeats=args.repeats, client_args=args.client_arg, origin_mss=args.origin_mss)
            for sample in range(1, args.repeats + 1):
                for mode, options, url in routes:
                    result, data = curl_result(options + [url + '/payload'], args.timeout)
                    validate_transfer(result, data, args.bytes)
                    emit(event='sample', label=args.label, mode=mode, sample=sample,
                         bytes=data['size_download'], seconds=data['time_total'],
                         Mbps=round(data['size_download'] * 8 / data['time_total'] / 1e6, 2))
            docker('stop', '--time', '1', server)
            result, data = curl_result(mux + ['https://biba-bench.invalid:8080/payload'], 6)
            if result.returncode == 0 or data.get('size_download', 0) != 0 or data.get('http_code') == 200:
                raise RuntimeError('negative control failed: request succeeded after tunnel server stopped')
            emit(event='negative_control', passed=True, rc=result.returncode, bytes=data.get('size_download'))
        finally:
            if child is not None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
            cleanup = [['docker', 'rm', '-f', name] for name in reversed(owned_containers)]
            if owned_network:
                cleanup.append(['docker', 'network', 'rm', tag])
            cleanup_errors = []
            for command in cleanup:
                try:
                    result = run(command, check=False)
                    # --rm containers already disappear after docker stop.
                    if result.returncode and 'No such container' not in result.stderr:
                        cleanup_errors.append(result.stderr.strip())
                except RuntimeError as error:
                    cleanup_errors.append(str(error))
            if cleanup_errors:
                raise RuntimeError('benchmark cleanup failed: ' + '; '.join(cleanup_errors))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        emit(event='error', message=str(error))
        sys.exit(1)
