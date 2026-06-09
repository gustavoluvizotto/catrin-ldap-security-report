__author__ = "Gustavo Luvizotto Cesar"

# Small Flask site that wraps perform_traceroute.sh.
# Run with: python3 app.py   (listens on 0.0.0.0:5003)

import os
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask("traceroute")

SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "perform_traceroute.sh")

# Allowed targets: hostnames and IPv4/IPv6 addresses only. The bash script
# validates this too, but rejecting early gives a cleaner error to the caller.
TARGET_RE = re.compile(r"^[A-Za-z0-9.:_-]+$")
PROTOCOLS = {"icmp", "tcp", "udp"}

# Parsing of `traceroute` text output into structured hops.
HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")          # leading hop number + rest
HOST_RE = re.compile(r"([A-Za-z0-9_.-]+)\s+\(([0-9a-fA-F:.]+)\)")  # name (ip)
RTT_RE = re.compile(r"([\d.]+)\s*ms")                    # "0.276 ms"


def parse_traceroute(stdout):
    """Turn raw traceroute output into a list of hop dicts."""
    hops = []
    for line in stdout.splitlines():
        m = HOP_LINE_RE.match(line)
        if not m:
            continue  # skips the "traceroute to ..." header line
        rest = m.group(2)
        host_m = HOST_RE.search(rest)
        hops.append({
            "hop": int(m.group(1)),
            "host": host_m.group(1) if host_m else None,
            "ip": host_m.group(2) if host_m else None,
            "rtts_ms": [float(x) for x in RTT_RE.findall(rest)],
            "timeouts": rest.count("*"),
        })
    return hops


@app.route("/help", methods=["GET"])
def help():
    return jsonify({
        "traceroute": {
            "description": "Run a traceroute to a target host.",
            "parameters": {
                "target": "Hostname or IP address to trace a route to.",
            },
            "example": 'curl -G -d "target=1.1.1.1" http://127.0.0.1:5003/traceroute',
        }
    }), 200


@app.route("/traceroute", methods=["GET"])
def traceroute():
    target = request.args.get("target", "").strip()
    protocol = "icmp" #request.args.get("protocol", "icmp").strip().lower()

    if not target or not TARGET_RE.match(target):
        return jsonify({"error": "Missing or invalid 'target' parameter."}), 400
    if protocol not in PROTOCOLS:
        return jsonify({"error": "Invalid 'protocol'. Use 'icmp', 'tcp', or 'udp'."}), 400

    try:
        result = subprocess.run(
            [SCRIPT_PATH, target, protocol],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Traceroute timed out."}), 504

    if result.returncode != 0:
        return jsonify({
            "error": "Traceroute failed.",
            "stderr": result.stderr,
        }), 500

    return jsonify({
        "target": target,
        "protocol": protocol,
        "hops": parse_traceroute(result.stdout),
        "raw": result.stdout,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, use_reloader=False, debug=True)
