#!/usr/bin/env python3
"""Split the captured TCP streams into one hex file per BGP message.

Reassembly is done by tshark ("follow TCP stream"), and the split uses nothing
but the 2-octet length field of the BGP header, so the crate under test has no
part in producing its own test vectors.

Usage: extract.py <directory with *.pcap> <output directory>
"""

import pathlib
import re
import subprocess
import sys

TYPE_NAMES = {1: "open", 2: "update", 3: "notification", 4: "keepalive", 5: "route-refresh"}
SENDERS = {"192.0.2.1": "frr", "192.0.2.2": "bird"}


def stream_count(pcap):
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-T", "fields", "-e", "tcp.stream"],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    return max((int(value) for value in out), default=-1) + 1


def follow(pcap, stream):
    """Return [(sender address, bytes)] in wire order for one TCP stream."""
    out = subprocess.run(
        ["tshark", "-r", str(pcap), "-q", "-z", f"follow,tcp,raw,{stream}"],
        check=True, capture_output=True, text=True,
    ).stdout
    nodes = dict(re.findall(r"^Node (\d): ([0-9.]+):\d+$", out, re.MULTILINE))
    chunks = []
    for line in out.splitlines():
        if re.fullmatch(r"\t?[0-9a-f]+", line):
            node = "1" if line.startswith("\t") else "0"
            chunks.append((nodes[node], bytes.fromhex(line.strip())))
    return chunks


def split_messages(data):
    messages = []
    while len(data) >= 19:
        length = int.from_bytes(data[16:18], "big")
        if length < 19 or length > len(data):
            raise SystemExit(f"cannot split stream at length field {length}")
        messages.append(data[:length])
        data = data[length:]
    if data:
        raise SystemExit(f"{len(data)} trailing octets in stream")
    return messages


def main():
    source, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
    for stale in output.glob("*.hex"):
        stale.unlink()
    for pcap in sorted(source.glob("*.pcap")):
        counter = 0
        for stream in range(stream_count(pcap)):
            buffers = {}
            order = []
            for sender, payload in follow(pcap, stream):
                if sender not in buffers:
                    buffers[sender] = b""
                    order.append(sender)
                buffers[sender] += payload
            for sender in order:
                for message in split_messages(buffers[sender]):
                    counter += 1
                    kind = TYPE_NAMES.get(message[18], f"type{message[18]}")
                    name = f"{pcap.stem}-{counter:02d}-{SENDERS[sender]}-{kind}.hex"
                    (output / name).write_text(message.hex() + "\n")
    (output / "VERSIONS").write_text((source / "versions.txt").read_text())


if __name__ == "__main__":
    main()
