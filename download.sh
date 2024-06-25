#!/bin/bash

go run prepare-download.go || exit 1
./zmap-data.sh || exit 1
./goscanner-data.sh || exit 1
./pyasn-data.sh || exit 1
