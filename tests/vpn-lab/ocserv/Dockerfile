# Alpine 3.20 is cached on the development machine; upgrade the entire container
# consistently because ocserv is currently packaged only in edge/testing.
FROM alpine:3.20
RUN printf '%s\n' https://dl-cdn.alpinelinux.org/alpine/edge/main https://dl-cdn.alpinelinux.org/alpine/edge/community https://dl-cdn.alpinelinux.org/alpine/edge/testing > /etc/apk/repositories \
 && apk upgrade --no-cache \
 && apk add --no-cache ocserv openssl iproute2 dnsmasq \
 && mkdir -p /etc/ocserv
COPY ocserv.conf /etc/ocserv/ocserv.conf
COPY start.sh /start.sh
RUN chmod 755 /start.sh
EXPOSE 443/tcp
CMD ["/start.sh"]
