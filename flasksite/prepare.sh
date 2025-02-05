#!/bin/sh

#go run latest_scans.go || exit 1

#./pyasn-data.sh || exit 1  # TODO implement cleanup script to remove old data (not found in the output of latest_scans.go)

/venv/bin/python3 create_database.py || exit 1
