#!/usr/bin/env bash
# Produce the decoder test vectors under tests/vectors/ by running FRR and BIRD
# against each other and recording what each of them puts on the wire.
#
# Needs docker, tshark and python3. Run from anywhere:
#   scripts/vectors/capture.sh
#
# The crate under test is not involved at any point, which is the point: these
# bytes come from two independent implementations.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
output="$(cd "$here/../../tests/vectors" && pwd)"
image="bgp4-vectors"
network="bgp4-vectors"
work="$(mktemp -d)"

cleanup() {
    docker rm -f bgp4-frr bgp4-bird >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT
cleanup
mkdir -p "$work"

docker build -q -t "$image" "$here" >/dev/null
# The bridge gateway is moved out of the way so the routers can use .1 and .2.
docker network create --ipv6 --subnet 192.0.2.0/24 --gateway 192.0.2.254 \
    --subnet 2001:db8:0:1::/64 "$network" >/dev/null

run_node() {
    docker run -d --name "$1" --hostname "$1" --network "$network" --ip "$2" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN "$image" >/dev/null
}
run_node bgp4-frr 192.0.2.1
run_node bgp4-bird 192.0.2.2

frr() { docker exec bgp4-frr vtysh "$@"; }
bird() { docker exec bgp4-bird birdc "$@"; }

wait_for_state() {
    for _ in $(seq 1 60); do
        if frr -c 'show bgp neighbors 192.0.2.2 json' 2>/dev/null | grep -q "\"bgpState\":\"$1\""; then
            return 0
        fi
        sleep 1
    done
    echo "session never reached $1" >&2
    exit 1
}

start_capture() {
    docker exec -d bgp4-bird tcpdump -i eth0 -U -w "/tmp/$1.pcap" tcp port 179
    sleep 1
}

stop_capture() {
    sleep 2
    docker exec bgp4-bird pkill -INT tcpdump
    sleep 1
    docker cp "bgp4-bird:/tmp/$1.pcap" "$work/$1.pcap" >/dev/null
}

docker exec bgp4-frr /usr/lib/frr/frrinit.sh start >/dev/null
docker exec bgp4-frr vtysh -c 'configure terminal' -c 'router bgp 64496' \
    -c 'neighbor 192.0.2.2 shutdown' >/dev/null
docker exec -d bgp4-bird bird -c /etc/bird/bird.conf -s /run/bird/bird.ctl
sleep 2

# Scenario 1: the session comes up, both sides announce, keepalives flow, then
# FRR shuts the neighbour down with a shutdown communication.
start_capture frr-shutdown
frr -c 'configure terminal' -c 'router bgp 64496' -c 'no neighbor 192.0.2.2 shutdown' >/dev/null
wait_for_state Established
sleep 8
frr -c 'configure terminal' -c 'router bgp 64496' \
    -c 'neighbor 192.0.2.2 shutdown message maintenance window' >/dev/null
stop_capture frr-shutdown

# Scenario 2: the session comes up again, then BIRD disables the protocol with
# a message.
bird disable peer >/dev/null
start_capture bird-disable
frr -c 'configure terminal' -c 'router bgp 64496' -c 'no neighbor 192.0.2.2 shutdown' >/dev/null
bird enable peer >/dev/null
wait_for_state Established
sleep 4
bird disable peer '"planned work"' >/dev/null
stop_capture bird-disable

# Scenario 3: BIRD expects the wrong AS from FRR and refuses the OPEN.
frr -c 'configure terminal' -c 'router bgp 64496' -c 'neighbor 192.0.2.2 shutdown' >/dev/null
bird configure '"/etc/bird/bird-wrong-peer-as.conf"' >/dev/null
start_capture wrong-peer-as
frr -c 'configure terminal' -c 'router bgp 64496' -c 'no neighbor 192.0.2.2 shutdown' >/dev/null
bird enable peer >/dev/null
sleep 8
stop_capture wrong-peer-as

{
    # First two words only: the rest of the line names the host kernel.
    docker exec bgp4-frr vtysh -c 'show version' | head -1 | cut -d' ' -f1,2
    docker exec bgp4-bird bird --version 2>&1 | head -1
} >"$work/versions.txt"

python3 -I "$here/extract.py" "$work" "$output"
