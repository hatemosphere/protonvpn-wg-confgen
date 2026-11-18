# The reference environment for the wire-parity goldens: Ubuntu 26.04 with
# Proton's own packages from their apt repository, i.e. the official Linux
# client's real HTTP stack (python-proton-core on the distro's aiohttp/OpenSSL).
# The release is part of what is recorded: the User-Agent names it and the
# ClientHello comes from its OpenSSL. Changing it means re-recording.
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db
ARG RELEASE_DEB=protonvpn-stable-release_1.0.8_all.deb
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq >/dev/null \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates wget gnupg >/dev/null \
 && update-ca-certificates --fresh >/dev/null \
 && wget -q "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/${RELEASE_DEB}" -O /tmp/release.deb \
 && dpkg -i /tmp/release.deb \
 && apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-proton-vpn-api-core tzdata >/dev/null \
 && ln -sf /usr/share/zoneinfo/Europe/Zurich /etc/localtime \
 && rm -rf /var/lib/apt/lists/* /tmp/release.deb
WORKDIR /parity
