__author__ = "Koen Teuwen"

import ipaddress
import traceback

import clickhouse_connect
import clickhouse_connect.driver
import clickhouse_connect.driver.client
import pandas
from create_database import ALERTS_TABLE_NAME
from flask import Response, jsonify


def push(
    clickhouse_client: clickhouse_connect.driver.client.Client, logs: list[dict]
) -> tuple[Response, int]:
    try:
        _ = clickhouse_client.insert(
            ALERTS_TABLE_NAME,
            [
                [
                    str(log["log.source.id"]),
                    int(log["log.id.uid"]),
                    str(log["rule.attacker.ip"]),
                    int(log["rule.attacker.port"]),
                    int(log["rule.sid"]),
                    str(log["rule.name"]),
                    pandas.to_datetime(log["@timestamp"]).to_pydatetime(),
                ]
                for log in logs
            ],
            column_names=[
                "id",
                "uid",
                "attacker",
                "attacker_port",
                "sid",
                "msg",
                "datetime",
            ],
        )
    except Exception as e:
        return jsonify({"error": traceback.format_exception(e)}), 500

    return Response(str(len(logs))), 200


def query(
    clickhouse_client: clickhouse_connect.driver.client.Client, ip_prefix: str
) -> tuple[Response, int]:
    """
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
    """

    try:
        converted_ip_prefix = ipaddress.ip_network(ip_prefix)
        if converted_ip_prefix.prefixlen < 20:  # max prefix length
            return (
                jsonify(
                    {"error": '"ip_prefix" length must be greater than or equal 20.'}
                ),
                400,
            )
    except ValueError as e:
        return (
            jsonify(
                {
                    "error": f'Invalid "ip_prefix". Error: {traceback.format_exception(e)}'
                }
            ),
            400,
        )

    try:
        result = _get_alert_data(clickhouse_client, ip_prefix)
        return jsonify(result), 200
    except KeyError as e:
        return (
            jsonify(
                {
                    "error": f"Invalid dataset key. Error: {traceback.format_exception(e)}"
                }
            ),
            500,
        )
    except Exception as e:
        return jsonify({"error": traceback.format_exception(e)}), 500


def _get_alert_data(client: clickhouse_connect.driver.client.Client, ip_prefix: str):
    zmap_pdf = client.query_df(
        f"SELECT * FROM {ALERTS_TABLE_NAME} WHERE isIPAddressInRange(attacker, '{ip_prefix}')"
    )
    return zmap_pdf.to_dict(orient="records")
