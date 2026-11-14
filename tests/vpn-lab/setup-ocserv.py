#!/usr/bin/env python3
"""Prepare a private, loopback-only native CSTP interoperability fixture."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "work/ocserv-lab"
CONTAINER = "sslray-ocserv-lab"
STATE.mkdir(parents=True, exist_ok=True)
os.chmod(STATE, 0o700)
password_file = STATE / "password"
if not password_file.exists():
    password_file.write_text(secrets.token_urlsafe(24) + "\n")
os.chmod(password_file, 0o600)
certificate = STATE / "server-cert.pem"
key = STATE / "server-key.pem"
if not certificate.exists() or not key.exists():
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
        "-subj", "/CN=SSLRay ocserv loopback lab", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout", str(key), "-out", str(certificate),
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.chmod(key, 0o600)
der = subprocess.run(["openssl", "x509", "-in", str(certificate), "-outform", "DER"], check=True, capture_output=True).stdout
profile = {
    "name": "Local ocserv lab", "protocol": "cisco", "host": "127.0.0.1", "port": 1443,
    "username": "sslray-test", "transport": "tls", "certificate_sha256": hashlib.sha256(der).hexdigest(),
}
(STATE / "profile.json").write_text(json.dumps(profile, indent=2) + "\n")
os.chmod(STATE / "profile.json", 0o600)
existing = subprocess.run(["docker", "inspect", CONTAINER], capture_output=True)
if existing.returncode == 0:
    metadata = json.loads(existing.stdout)[0]
    ports = metadata["HostConfig"]["PortBindings"]
    assert ports == {"443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1443"}]}, "Existing container has unexpected port exposure"
    if metadata["State"]["Running"]:
        print("Reusing the existing loopback-only ocserv lab at 127.0.0.1:1443")
        raise SystemExit(0)
    subprocess.run(["docker", "rm", CONTAINER], check=True, stdout=subprocess.DEVNULL)
subprocess.run(["docker", "build", "-t", "sslray-ocserv-lab:local", str(ROOT / "tests/vpn-lab/ocserv")], check=True)
subprocess.run([
    "docker", "run", "-d", "--name", CONTAINER, "--cap-add", "NET_ADMIN",
    "-p", "127.0.0.1:1443:443/tcp", "-v", str(STATE) + ":/state", "sslray-ocserv-lab:local",
], check=True, stdout=subprocess.DEVNULL)
print("Started the private ocserv lab at 127.0.0.1:1443; credentials were not printed")
