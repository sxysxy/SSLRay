#!/bin/sh
set -eu
mkdir -p /dev/net
[ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200
lab_password=$(cat /state/password)
printf '%s\n%s\n' "$lab_password" "$lab_password" | ocpasswd -c /state/ocpasswd sslray-test >/dev/null 2>&1
unset lab_password
dnsmasq --no-daemon --conf-file=/dev/null --no-resolv --no-hosts --listen-address=127.0.0.1,10.91.0.1 --address=/#/10.91.0.99 >/dev/null 2>&1 &
exec ocserv --foreground --debug 1 --config /etc/ocserv/ocserv.conf
