#!/usr/bin/env python3

# ACK to Remi Hendriks for the original shell script this is based on.
#
# Python equivalent of perform_mtr.sh, using the icmplib library to perform the
# measurement directly (no external mtr binary or container).
# example: ./perform_mtr.py 1.1.1.1

import argparse
import socket
import statistics
import time

from icmplib import traceroute

# Number of packets to send for each hop.
PACKET_COUNT = 1


def perform_mtr(target, protocol):
    if protocol != "icmp":
        raise ValueError(
            f"Protocol '{protocol}' is not supported; icmplib performs ICMP "
            "traceroutes only."
        )

    source_hostname = socket.gethostname()
    output_file = f"mtr_results/mtr_{target}.csv"
    start_time = int(time.time())

    print(f"Creating new results file: {output_file}")
    header = (
        "hostname,Mtr_Version,Start_Time,Status,Host,Hop,Ip,Asn,"
        "Loss%,Snt, ,Last,Avg,Best,Wrst,StDev,"
    )
    with open(output_file, "w") as f:
        f.write(header + "\n")

    print(f"Running MTR for target: {target} using protocol: {protocol}")

    # privileged=True uses raw sockets (needs root); on systems that allow
    # unprivileged ICMP you can set this to False.
    hops = traceroute(target, count=PACKET_COUNT) #, privileged=True)

    with open(output_file, "a") as f:
        for hop in hops:
            rtts = hop.rtts
            last = rtts[-1] if rtts else 0.0
            stdev = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
            row = [
                source_hostname,        # hostname
                "icmplib",              # Mtr_Version
                start_time,             # Start_Time
                "OK",                   # Status
                target,                 # Host
                hop.distance,           # Hop
                hop.address,            # Ip
                "AS???",                # Asn (not resolved by icmplib)
                f"{hop.packet_loss * 100:.2f}",  # Loss%
                hop.packets_sent,       # Snt
                "",                     # (blank column in mtr CSV)
                f"{last:.2f}",          # Last
                f"{hop.avg_rtt:.2f}",   # Avg
                f"{hop.min_rtt:.2f}",   # Best
                f"{hop.max_rtt:.2f}",   # Wrst
                f"{stdev:.2f}",         # StDev
            ]
            f.write(",".join(str(field) for field in row) + "\n")

    print("--------------------------------------------------")
    print(f"MTR data collection complete for {target}.")


def main():
    parser = argparse.ArgumentParser(
        description="Run an MTR measurement against a target and store the "
        "results as CSV in mtr_results/."
    )
    parser.add_argument("target", help="Target IP address or domain name")
    parser.add_argument(
        "protocol",
        nargs="?",
        default="icmp",
        choices=["icmp", "tcp", "udp"],
        help="Protocol to use. Default is 'icmp'.",
    )
    args = parser.parse_args()

    perform_mtr(args.target, args.protocol)


if __name__ == "__main__":
    main()
