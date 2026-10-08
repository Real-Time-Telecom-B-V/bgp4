# Two independent BGP implementations in one image, used only to produce the
# decoder test vectors under tests/vectors/. Never part of the crate.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends frr bird2 tcpdump iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons \
    && mkdir -p /run/bird

COPY frr.conf /etc/frr/frr.conf
COPY bird.conf bird-wrong-peer-as.conf bird-four-octet-as.conf \
    bird-two-octet-session.conf /etc/bird/

CMD ["sleep", "infinity"]
