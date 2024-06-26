__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

import ipaddress
from flask import jsonify
import pandas as pd

import pyspark.sql.functions as psf
import pyspark.sql.types as pst


def scanning_query(ip_prefix: str, dataset_scanning: dict) -> tuple:
    '''
    return:
        str([{
            (mandatory)
            "ip": str,
            "port": int,
            "scan_date": str,
            (optional - depend on app layer scan)
            "hosts.server_name": str,
            "hosts.protocol": str,
            "hosts.cipher": str,
            "hosts.result": str,
            "hosts.cert_hash": str,
            "hosts.pub_key_hash": str,
            "certs.subject": list(str),
            "certs.issuer": list(str),
        }]), int
    '''
    # TODO implement ASN query

    try:
        converted_ip_prefix = ipaddress.ip_network(ip_prefix)
        if converted_ip_prefix.prefixlen < 20:  # max prefix length
            return jsonify({"error": '"ip_prefix" length must be greater than or equal 20.'}), 400
    except ValueError as e:
        return jsonify({"error": f'Invalid "ip_prefix". Error: {e}'}), 400

    try:
        result1 = _get_tcp_layer_info(ip_prefix, dataset_scanning["zmap"])
        result2 = _get_app_layer_info(ip_prefix, dataset_scanning["goscanner"])
        result = merge_list_dict(result1, result2)
        return jsonify(result), 200
    except KeyError as e:
        return jsonify({"error": f'Invalid dataset key. Error: {e}'}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _get_tcp_layer_info(ip_prefix: str, zmap_df):
    zmap_df = zmap_df.withColumn("is_ip_in_prefix",
                                 is_ip_in_prefix_udf(psf.col("ipv4"),
                                                     psf.lit(ip_prefix)))
    zmap_dict = zmap_df.filter(
        psf.col("is_ip_in_prefix") == True
    ).drop("is_ip_in_prefix").toPandas().to_dict(orient="records")
    return zmap_dict


def is_ip_in_prefix(ip: str, prefix: str) -> bool:
    return ipaddress.ip_address(ip) in ipaddress.ip_network(prefix)


is_ip_in_prefix_udf = psf.udf(is_ip_in_prefix, pst.BooleanType())


def _get_app_layer_info(ip_prefix: str, goscanner_df):
    goscanner_df = goscanner_df.withColumn("is_ip_in_prefix",
                                           is_ip_in_prefix_udf(psf.col("ipv4"),
                                                               psf.lit(ip_prefix)))
    goscanner_dict = goscanner_df.filter(
        psf.col("is_ip_in_prefix") == True
    ).drop("is_ip_in_prefix").toPandas().to_dict(orient="records")
    return goscanner_dict


def merge_list_dict(data1, data2):
    for i in data1:
        for j in data2:
            if i["ipv4"] == j["ipv4"] and i["port"] == j["port"]:  # and i["scan_date"] == j["scan_date"]:
                i.update(j)
    return data1
