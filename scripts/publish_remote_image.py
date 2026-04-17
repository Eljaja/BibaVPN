from __future__ import annotations

import argparse
import io
import posixpath
import tarfile
from pathlib import Path

import paramiko


EXCLUDE_PARTS = {".git", "target", "__pycache__", "node_modules", ".venv"}


def should_include(path: Path) -> bool:
    return not any(part in EXCLUDE_PARTS for part in path.parts)


def exec_checked(
    ssh: paramiko.SSHClient, command: str, stdin_data: str | None = None
) -> tuple[str, str]:
    stdin, stdout, stderr = ssh.exec_command(command)
    if stdin_data is not None:
        stdin.write(stdin_data)
        stdin.flush()
        stdin.channel.shutdown_write()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    if code != 0:
        raise RuntimeError(
            f"remote command failed ({code}): {command}\nstdout:\n{out}\nstderr:\n{err}"
        )
    return out, err


def upload_repo(
    ssh: paramiko.SSHClient, local_dir: Path, remote_dir: str, remote_name: str
) -> None:
    exec_checked(ssh, f"mkdir -p {remote_dir}")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for path in local_dir.rglob("*"):
            if not should_include(path):
                continue
            arcname = Path(remote_name) / path.relative_to(local_dir)
            tar.add(path, arcname=str(arcname))
    buffer.seek(0)

    sftp = ssh.open_sftp()
    try:
        remote_tar = posixpath.join(remote_dir, f"{remote_name}.tar")
        with sftp.file(remote_tar, "wb") as handle:
            handle.write(buffer.read())
        exec_checked(
            ssh,
            f"rm -rf {posixpath.join(remote_dir, remote_name)} && "
            f"tar xf {remote_tar} -C {remote_dir} && "
            f"rm -f {remote_tar}",
        )
    finally:
        sftp.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--remote-dir", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--docker-username", required=True)
    parser.add_argument("--docker-password", required=True)
    args = parser.parse_args()

    repo_dir = Path(__file__).resolve().parents[1]
    remote_name = "biba-vpn"
    remote_repo_dir = posixpath.join(args.remote_dir, remote_name)
    full_image = f"{args.image}:{args.tag}"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=args.host,
        port=args.port,
        username=args.username,
        password=args.password,
        timeout=20,
    )
    try:
        exec_checked(
            ssh,
            "docker --version && "
            "(docker compose version >/dev/null 2>&1 || true)",
        )
        upload_repo(ssh, repo_dir, args.remote_dir, remote_name)
        build_cmd = (
            f"cd {remote_repo_dir} && "
            f"docker build -f docker/Dockerfile.server -t {full_image} ."
        )
        out, err = exec_checked(ssh, build_cmd)
        print(out)
        if err.strip():
            print(err)

        login_cmd = f"docker login -u {args.docker_username} --password-stdin"
        out, err = exec_checked(ssh, login_cmd, stdin_data=args.docker_password + "\n")
        print(out)
        if err.strip():
            print(err)

        push_cmd = f"docker push {full_image}"
        out, err = exec_checked(ssh, push_cmd)
        print(out)
        if err.strip():
            print(err)
    finally:
        ssh.close()


if __name__ == "__main__":
    main()
