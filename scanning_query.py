__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

import ipaddress
from flask import jsonify


def scanning_query(ip_prefix: str, dataset_scanning: dict) -> tuple:
    '''
    return:
        str({
            (mandatory)
            "ip": value,
            "port_scandate": [(value, value), ...],
            (optional - depend on app layer scan)
            "hosts.server_name": value,
            "hosts.protocol": value,
            "hosts.cipher": value,
            "hosts.result": value,
            "hosts.cert_hash": value,
            "hosts.pub_key_hash": value,
            "certs.subject": value,
            "certs.issuer": value,
            "certs.cn": value,
        }), int
    '''
    # TODO implement ASN query

    try:
        ip_prefix = ipaddress.ip_network(ip_prefix)
        if ip_prefix.prefixlen < 20:  # max prefix length
            return jsonify({"error": "\"ip_prefix\" length must be less than 20."}), 400
    except ValueError as e:
        return jsonify({"error": f"Invalid \"ip_prefix\". Error: {e}"}), 400

    try:
        result = _get_tcp_layer_info(ip_prefix)
        return jsonify(result)
    except KeyError:
        return jsonify({"error": f"Column '{column}' does not exist in the dataset."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _get_tcp_layer_info(ip_prefix) -> dict:
    return {}


def _get_app_layer_info() -> dict:
    return {}