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
                ipython \
                ipaddress \
                pyasn \
                cryptography \
                pyspark
