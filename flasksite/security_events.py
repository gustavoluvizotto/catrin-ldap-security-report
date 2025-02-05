__author__ = "Koen Teuwen"

import ipaddress
from datetime import datetime

import clickhouse_connect
import clickhouse_connect.driver
import clickhouse_connect.driver.client
from create_database import ALERTS_TABLE_NAME
from flask import Response, jsonify

ALERTS_DIR_FORMAT = "catrin/measurements/tool=goscanner/format=raw/port={port}/scan={scan}/result={result}/year={year}/month={month:02}/day={day:02}"


def push(clickhouse_client: clickhouse_connect.driver.client.Client, logs: list[dict]) -> tuple[Response, int]:
    for log in logs:
        try:
            _ = clickhouse_client.query(
f"INSERT INTO {ALERTS_TABLE_NAME} \
SELECT {log['log.source.id']} as id, {log['log.id.uid']} as uid, {log['rule.attacker.ip']} as attacker, {log['rule.attacker.port']} as attacker_port, {log['rule.sid']} as sid, {log['rule.name']} as msg, formatDateTime(toDate('{log['@timestamp']}'), '%F', 'Etc/UTC') as datetime"
)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return Response(), 200

def query(clickhouse_client: clickhouse_connect.driver.client.Client, ip_prefix: str) -> tuple[Response, int]:
    '''
    return:
        str([{
            (mandatory)
            "id": str,
            "uid": int,
            "attacker": str,
            "sid": int,
            "msg": str,
            "datetime": str,
            (optional)
            "attacker_port": int,
        }]), int
    '''

    try:
        converted_ip_prefix = ipaddress.ip_network(ip_prefix)
        if converted_ip_prefix.prefixlen < 20:  # max prefix length
            return jsonify({"error": '"ip_prefix" length must be greater than or equal 20.'}), 400
    except ValueError as e:
        return jsonify({"error": f'Invalid "ip_prefix". Error: {e}'}), 400

    try:
        result = _get_alert_data(clickhouse_client, ip_prefix)
        return jsonify(result), 200
    except KeyError as e:
        return jsonify({"error": f'Invalid dataset key. Error: {e}'}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _get_alert_data(client: clickhouse_connect.driver.client.Client, ip_prefix: str):
    zmap_pdf = client.query_df(f"SELECT * FROM {ALERTS_TABLE_NAME} WHERE isIPAddressInRange(attacker, '{ip_prefix}')")
    return zmap_pdf.to_dict(orient="records")