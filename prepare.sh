#!/bin/bash

go run latest_scans.go || exit 1
#./zmap-data.sh || exit 1
#./goscanner-data.sh || exit 1
#./pyasn-data.sh || exit 1  # TODO implement cleanup script to remove old data (not found in the output of latest_scans.go)

# Install ClickHouse before this script
# https://clickhouse.com/docs/en/install#available-installation-options
# service clickhouse-server start

venv/bin/python create_database.py || exit 1
