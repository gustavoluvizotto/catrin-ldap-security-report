__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

import traceback
import math

import ipaddress
import pandas as pd
from flask import jsonify

from create_database import ZMAP_TABLE_NAME, HOSTS_TABLE_NAME, CERTS_TABLE_NAME, LDAP_TABLE_NAME, STARTTLS_TABLE_NAME
from query_utils import decode_cert, merge_list_dict, cipher_to_description, tls_version_to_string


def scanning_report(clickhouse_client, ip_prefix: str):
    '''
    return:
        str([{
            nr_ip_addresses: int,
            ports: list(int),
            ciphers: dict({cipher: int}),
            protocols: dict({protocol: int}),
            nr_invalid_date_cert: int,
            nr_ldap_servers: int,
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
        nr_ips = _get_nr_ips(clickhouse_client, ip_prefix)
        ports = _get_ports(clickhouse_client, ip_prefix)
        ciphers = _get_ciphers(clickhouse_client, ip_prefix)
        protocols = _get_protocols(clickhouse_client, ip_prefix)
        nr_invalid_date_cert = _get_nr_invalid_date_cert(clickhouse_client, ip_prefix)
        nr_ldap_servers = _get_nr_ldap_servers(clickhouse_client, ip_prefix)
        result = {
            "nr_ip_addresses": nr_ips,
            "ports": ports,
            "ciphers": ciphers,
            "protocols": protocols,
            "nr_invalid_date_cert": nr_invalid_date_cert,
            "nr_ldap_servers": nr_ldap_servers,
        }
        return jsonify(result), 200
    except Exception as e:
        #stack_trace = traceback.format_exc()
        return jsonify({"error": str(e)}), 500

def _get_nr_ips(clickhouse_client, ip_prefix: str) -> int:
    query = f"SELECT countDistinct(ipv4) AS nr_ip_addresses FROM {ZMAP_TABLE_NAME} WHERE isIPAddressInRange(ipv4, '{ip_prefix}')"
    result_pdf = clickhouse_client.query_df(query)
    return int(result_pdf["nr_ip_addresses"][0])

def _get_ports(clickhouse_client, ip_prefix: str) -> list:
    query = f"SELECT DISTINCT port FROM {ZMAP_TABLE_NAME} WHERE isIPAddressInRange(ipv4, '{ip_prefix}')"
    result_pdf = clickhouse_client.query_df(query)
    return result_pdf["port"].tolist()

def _get_ciphers(clickhouse_client, ip_prefix: str) -> dict:
    query = f"SELECT cipher, count(cipher) AS count FROM {HOSTS_TABLE_NAME} WHERE isIPAddressInRange(ipv4, '{ip_prefix}') GROUP BY cipher"
    result_pdf = clickhouse_client.query_df(query)
    if not result_pdf.empty:
        result_pdf = result_pdf[(result_pdf["cipher"].notnull())]
        result_pdf["cipher"] = result_pdf["cipher"].apply(lambda x: cipher_to_description(x))
    return dict(zip(result_pdf["cipher"].astype(str), result_pdf["count"].astype(int)))

def _get_protocols(clickhouse_client, ip_prefix: str) -> dict:
    query = f"SELECT protocol, count(protocol) AS count FROM {HOSTS_TABLE_NAME} WHERE isIPAddressInRange(ipv4, '{ip_prefix}') GROUP BY protocol"
    result_pdf = clickhouse_client.query_df(query)
    if not result_pdf.empty:
        result_pdf = result_pdf[(result_pdf["protocol"].notnull() & result_pdf["protocol"] != 0)]
        result_pdf["protocol"] = result_pdf["protocol"].apply(lambda x: tls_version_to_string(int(x)))
    return dict(zip(result_pdf["protocol"].astype(str), result_pdf["count"].astype(int)))

def _get_nr_invalid_date_cert(clickhouse_client, ip_prefix: str) -> int:
    query = f"SELECT {HOSTS_TABLE_NAME}.ipv4, {HOSTS_TABLE_NAME}.protocol, {HOSTS_TABLE_NAME}.cipher, {HOSTS_TABLE_NAME}.cert_hash, {HOSTS_TABLE_NAME}.pub_key_hash, {CERTS_TABLE_NAME}.cert, {HOSTS_TABLE_NAME}.scan_date, {HOSTS_TABLE_NAME}.port FROM {HOSTS_TABLE_NAME} INNER JOIN {CERTS_TABLE_NAME} ON {HOSTS_TABLE_NAME}.cert_id={CERTS_TABLE_NAME}.id AND {HOSTS_TABLE_NAME}.scan_date={CERTS_TABLE_NAME}.scan_date AND {HOSTS_TABLE_NAME}.port={CERTS_TABLE_NAME}.port WHERE isIPAddressInRange({HOSTS_TABLE_NAME}.ipv4, '{ip_prefix}')"
    certs_pdf = clickhouse_client.query_df(query)
    nr_invalid_cert_date = 0
    if not certs_pdf.empty:
        certs_pdf = certs_pdf.apply(decode_cert, axis=1)
        certs_pdf = certs_pdf.drop("cert", axis=1)
        certs_pdf = certs_pdf.apply(is_valid_date_certs, axis=1)
        nr_invalid_cert_date = certs_pdf["is_cert_valid"].value_counts().get(False, 0)
    return int(nr_invalid_cert_date)

def is_valid_date_certs(cert_pdf):
    not_before = cert_pdf["not_valid_before"]
    not_after = cert_pdf["not_valid_after"]
    if not_before is None or not_after is None:
        cert_pdf["is_cert_valid"] = False
        return cert_pdf
    scan_date = cert_pdf["scan_date"]
    cert_pdf["is_cert_valid"] = not_before <= scan_date <= not_after
    return cert_pdf

def _get_nr_ldap_servers(clickhouse_client, ip_prefix: str) -> int:
    query = f"SELECT {HOSTS_TABLE_NAME}.ipv4, {LDAP_TABLE_NAME}.ldap_server, {HOSTS_TABLE_NAME}.scan_date, {HOSTS_TABLE_NAME}.port FROM {HOSTS_TABLE_NAME} INNER JOIN {LDAP_TABLE_NAME} ON {HOSTS_TABLE_NAME}.id={LDAP_TABLE_NAME}.id AND {HOSTS_TABLE_NAME}.scan_date={LDAP_TABLE_NAME}.scan_date AND {HOSTS_TABLE_NAME}.port={LDAP_TABLE_NAME}.port WHERE isIPAddressInRange({HOSTS_TABLE_NAME}.ipv4, '{ip_prefix}') AND {LDAP_TABLE_NAME}.ldap_server=1"
    ldap_pdf = clickhouse_client.query_df(query)
    query = f"SELECT {HOSTS_TABLE_NAME}.ipv4, {STARTTLS_TABLE_NAME}.ldap_server, {HOSTS_TABLE_NAME}.scan_date, {HOSTS_TABLE_NAME}.port FROM {HOSTS_TABLE_NAME} INNER JOIN {STARTTLS_TABLE_NAME} ON {HOSTS_TABLE_NAME}.id={STARTTLS_TABLE_NAME}.id AND {HOSTS_TABLE_NAME}.scan_date={STARTTLS_TABLE_NAME}.scan_date AND {HOSTS_TABLE_NAME}.port={STARTTLS_TABLE_NAME}.port WHERE isIPAddressInRange({HOSTS_TABLE_NAME}.ipv4, '{ip_prefix}') AND {STARTTLS_TABLE_NAME}.ldap_server=1"
    starttls_ldap_pdf = clickhouse_client.query_df(query)
    result = merge_list_dict(ldap_pdf.to_dict(orient="records"), starttls_ldap_pdf.to_dict(orient="records"))
    nr_ldap_servers = len(result)
    return int(nr_ldap_servers)
