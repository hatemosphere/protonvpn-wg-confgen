# The reference environment for the wire-parity goldens: Ubuntu 24.04 with
# Proton's own packages from their apt repository, i.e. the official Linux
# client's real HTTP stack (python-proton-core on the distro's aiohttp/OpenSSL).
# It must stay on 24.04: the User-Agent names that release and the recorded TLS
# ClientHello comes from its OpenSSL. Bump the digest, not the tag.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac

# Roots removed from Mozilla's NSS on 2026-10-20 after eight eMudhra
# intermediates had their private keys compromised (Mozilla bug 2083449). Ubuntu's
# ca-certificates still ships some of them, so they are distrusted here before
# anything is fetched over TLS. The build fails if any of them is still trusted.
ARG DISTRUSTED_ROOTS="emSign_ECC_Root_CA_-_G3 emSign_Root_CA_-_C1 emSign_ECC_Root_CA_-_C3"
ARG RELEASE_DEB=protonvpn-stable-release_1.0.8_all.deb

RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq >/dev/null \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates openssl wget gnupg >/dev/null \
 && for root in $DISTRUSTED_ROOTS; do \
      sed -i "s|^mozilla/${root}.crt$|!mozilla/${root}.crt|" /etc/ca-certificates.conf; \
    done \
 && update-ca-certificates --fresh >/dev/null \
 && for root in $DISTRUSTED_ROOTS; do \
      if [ -e "/etc/ssl/certs/${root}.pem" ]; then echo "still trusted: ${root}" >&2; exit 1; fi; \
      label=$(echo "$root" | tr '_' ' '); \
      if openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt \
           | openssl pkcs7 -print_certs -noout | grep -q "CN *= *${label}$"; then \
        echo "still in bundle: ${label}" >&2; exit 1; \
      fi; \
    done \
 && wget -q "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/${RELEASE_DEB}" -O /tmp/release.deb \
 && dpkg -i /tmp/release.deb \
 && apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-proton-vpn-api-core tzdata >/dev/null \
 && ln -sf /usr/share/zoneinfo/Europe/Zurich /etc/localtime \
 && rm -rf /var/lib/apt/lists/* /tmp/release.deb
WORKDIR /parity
