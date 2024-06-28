#!/bin/bash

# make sure to have Python and Java (for pyspark) installed

if [[ ! -d venv ]]; then
    python3 -m venv venv
    venv/bin/pip install --upgrade pip
fi

venv/bin/pip install \
                pip-autoremove \
                pandas \
                flask \
                flask-cors \
                ipaddress \
                ipython \
                pyasn \
                cryptography \
                clickhouse-connect

go run latest_scans.go || exit 1

#./pyasn-data.sh || exit 1  # TODO implement cleanup script to remove old data (not found in the output of latest_scans.go)

venv/bin/python create_database.py || exit 1
