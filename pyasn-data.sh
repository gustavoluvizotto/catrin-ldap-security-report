#!/bin/bash

DATES_FROM_FILE="pyasn_dates-from.txt"
REDUCED_DATES_FROM_FILE="reduced_pyasn_dates-from.txt"
OUTPUT_DIR="research_data/pyasn"

function format_date() {
    local date="$1"

    year=${date:0:4}
    month=${date:4:2}
    day=${date:6:2}

    formatted_date="${year}-${month}-${day}"
    echo "${formatted_date}"
}

cat zmap-port-date.csv | awk -F',' '{print $2}' > tmp.txt
cat goscanner-port-date.csv | awk -F',' '{print $4}' >> tmp.txt
cat tmp.txt | sort | uniq > "${DATES_FROM_FILE}"
rm -rf tmp.txt

rm -rf "${REDUCED_DATES_FROM_FILE}"
while IFS= read -r date_str; do
    DOWNLOADED_FILES=$(find "${OUTPUT_DIR}" -type f -exec basename {} \;)
    if echo "${DOWNLOADED_FILES}" | grep -q "${date_str}"; then
        echo "A dat file from ${date_str} already present. Skipping"
    else
        echo "${date_str}" >> "${REDUCED_DATES_FROM_FILE}"
    fi
done < ${DATES_FROM_FILE}

rm -rf "${DATES_FROM_FILE}"

if [ -f "${REDUCED_DATES_FROM_FILE}" ]; then
    venv/bin/pyasn_util_download.py --dates-from-file "${REDUCED_DATES_FROM_FILE}"

    START_DATE=$(format_date "$(head -n 1 "${REDUCED_DATES_FROM_FILE}")")
    END_DATE=$(format_date "$(tail -1 "${REDUCED_DATES_FROM_FILE}")")
    venv/bin/pyasn_util_convert.py --bulk "${START_DATE}" "${END_DATE}"

    mv ./*.dat "${OUTPUT_DIR}" 2>/dev/null
    rm -rf rib.* 2>/dev/null
    rm -rf "${REDUCED_DATES_FROM_FILE}"
fi
