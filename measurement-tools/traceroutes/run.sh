#!/usr/bin/env bash
#
# Bring up the measurement server, or run a one-off measurement.
#
# Usage:
#   ./run.sh                      # build + start the HTTP measurement server
#   ./run.sh <destination> [proto]  # run a single measurement and exit
#
# Override the compose command if you use podman:
#   COMPOSE="podman-compose" ./run.sh
set -euo pipefail

cd "$(dirname "$0")"

COMPOSE="${COMPOSE:-docker compose}"

# Build the image first (works with both docker compose and podman-compose).
$COMPOSE build measurement-server

if [[ $# -ge 1 ]]; then
    # One-off measurement via the container entrypoint (destination as argument).
    exec $COMPOSE run --rm measurement-server "$@"
else
    # Start the long-running HTTP server.
    exec $COMPOSE up measurement-server
fi
