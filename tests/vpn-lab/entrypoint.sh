#!/bin/sh
set -eu
umask 077
mkdir -p /state /run/ocserv
cd /state
if [ ! -f ca.crt ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout ca.key -out ca.crt -subj '/CN=SSLRay isolated test CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
  for identity in server client; do
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$identity.key" -out "$identity.csr" -subj "/CN=sslray-$identity"
    if [ "$identity" = server ]; then
      printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > identity.ext
    else
      printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' > identity.ext
    fi
    openssl x509 -req -in "$identity.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -out "$identity.crt" -extfile identity.ext
  done
  openssl rand -hex 16 > test-password
fi
if [ "${1:-openvpn}" = openvpn ]; then
  cat > /state/openvpn.conf <<'CONFIG'
port 1194
proto udp
dev tun
server 10.88.0.0 255.255.255.0
topology subnet
ca /state/ca.crt
cert /state/server.crt
key /state/server.key
dh none
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
keepalive 10 60
persist-key
persist-tun
verb 3
CONFIG
  exec openvpn --config /state/openvpn.conf
fi
if [ "$1" = ocserv ]; then
  if [ ! -f /state/ocpasswd ]; then
    { cat test-password; cat test-password; } | ocpasswd -c /state/ocpasswd sslray-test
  fi
  cat > /state/ocserv.conf <<'CONFIG'
auth = "plain[passwd=/state/ocpasswd]"
tcp-port = 1443
udp-port = 1443
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/ocserv/socket
isolate-workers = false
server-cert = /state/server.crt
server-key = /state/server.key
ca-cert = /state/ca.crt
device = vpns
ipv4-network = 10.89.0.0
ipv4-netmask = 255.255.255.0
dns = 10.89.0.1
max-clients = 4
max-same-clients = 2
keepalive = 30
dpd = 10
try-mtu-discovery = false
route = 10.89.0.0/255.255.255.0
cisco-client-compat = true
CONFIG
  exec ocserv -f -c /state/ocserv.conf
fi
printf 'Expected openvpn or ocserv\n' >&2
exit 2
