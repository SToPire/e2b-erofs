FROM curlimages/curl:8.12.1 AS ca

FROM debian:bookworm-slim

# Bootstrap HTTPS downloads using a real CA bundle. The Debian ca-certificates
# package below installs the distribution's final trust store.
COPY --from=ca /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Real packages from the declared Debian provisioning profile. The integration
# test still runs E2B's complete provisioning script and boots real systemd;
# preinstalling its packages keeps the guest independent of external networking.
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    systemd systemd-sysv openssh-server sudo chrony socat curl ca-certificates \
    fuse3 iptables git nfs-common less nftables iputils-ping jq iproute2 \
    && rm -rf /var/lib/apt/lists/*
