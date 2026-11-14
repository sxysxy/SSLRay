FROM debian:bookworm-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openvpn ocserv openssl iproute2 iptables && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/sslray-vpn-lab
RUN chmod 755 /usr/local/bin/sslray-vpn-lab
ENTRYPOINT ["/usr/local/bin/sslray-vpn-lab"]
