#!/bin/bash

DOWNLOAD_DIR="research_data/catrin/"
mkdir -p ${DOWNLOAD_DIR}
cd ${DOWNLOAD_DIR} || exit 1

while IFS= read -r line
do
    IFS=',' read -r port timestamp <<< "${line}"
    year="${timestamp:0:4}"
    month="${timestamp:4:2}"
    day="${timestamp:6:2}"
    p="measurements/tool=zmap/dataset=default/port=${port}/year=${year}/month=${month}/day=${day}/"
    mkdir -p "${p}"
    #podman run --network=host --rm -v "$(pwd)":/root/shared_dir mc cp -r storage/catrin/"${p}" shared_dir/"${p}"
    mc cp -r storage/catrin/"${p}" "${p}"
done < ../../zmap-port-date.csv

IFS=$'\n'
