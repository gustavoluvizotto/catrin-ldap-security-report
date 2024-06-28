__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from datetime import datetime

import ipaddress
from flask import jsonify
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import pyspark.sql.functions as psf
import pyspark.sql.types as pst

from create_database import ZMAP_TABLE_NAME, HOSTS_TABLE_NAME, CERTS_TABLE_NAME, LDAP_TABLE_NAME, STARTTLS_TABLE_NAME


def scanning_query(clickhouse_client, ip_prefix: str, dataset_scanning: dict) -> tuple:
    '''
    return:
        str([{
            (mandatory)
            "ip": str,
            "port": int,
            "scan_date": str,
            (optional - depend on app layer scan)
            "server_name": str,
            "resultString": str,
            (optional - depend on tls comm)
            "protocol": str,
            "cipher": str,
            "cert_hash": str,
            "pub_key_hash": str,
            "subject": list(str),
            "issuer": list(str),
            (optional - depend on ldap scan)
            "ldap_server": int(1 or 0),
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
        #result1 = _get_tcp_layer_info_spark(ip_prefix, dataset_scanning["zmap"])
        #result2 = _get_app_layer_info_spark(ip_prefix, dataset_scanning["goscanner"])
        result1 = _get_tcp_layer_info(clickhouse_client, ip_prefix)
        result2 = _get_app_layer_info(clickhouse_client, ip_prefix)
        result = merge_list_dict(result1, result2)
        return jsonify(result), 200
    except KeyError as e:
        return jsonify({"error": f'Invalid dataset key. Error: {e}'}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _get_tcp_layer_info(client, ip_prefix: str):
    zmap_pdf = client.query_df(f"SELECT * FROM {ZMAP_TABLE_NAME} WHERE isIPAddressInRange(ipv4, '{ip_prefix}')")
    return zmap_pdf.to_dict(orient="records")


def _get_app_layer_info(client, ip_prefix: str):
    hosts_pdf = client.query_df(f"SELECT ipv4, port, scan_date, server_name, resultString FROM {HOSTS_TABLE_NAME} WHERE isIPAddressInRange(ipv4, '{ip_prefix}')")
    hosts_dict = hosts_pdf.to_dict(orient="records")

    certs_pdf = client.query_df(f"SELECT {HOSTS_TABLE_NAME}.ipv4, {HOSTS_TABLE_NAME}.protocol, {HOSTS_TABLE_NAME}.cipher, {HOSTS_TABLE_NAME}.cert_hash, {HOSTS_TABLE_NAME}.pub_key_hash, {CERTS_TABLE_NAME}.cert, {HOSTS_TABLE_NAME}.scan_date, {HOSTS_TABLE_NAME}.port FROM {HOSTS_TABLE_NAME} INNER JOIN {CERTS_TABLE_NAME} ON {HOSTS_TABLE_NAME}.cert_id={CERTS_TABLE_NAME}.id AND {HOSTS_TABLE_NAME}.scan_date={CERTS_TABLE_NAME}.scan_date AND {HOSTS_TABLE_NAME}.port={CERTS_TABLE_NAME}.port WHERE isIPAddressInRange({HOSTS_TABLE_NAME}.ipv4, '{ip_prefix}')")
    if not certs_pdf.empty:
        certs_pdf = certs_pdf.apply(decode_cert, axis=1)
        certs_pdf = certs_pdf.drop("cert", axis=1)
    certs_dict = certs_pdf.to_dict(orient="records")
    result1 = merge_list_dict(hosts_dict, certs_dict)

    ldap_pdf = client.query_df(f"SELECT {HOSTS_TABLE_NAME}.ipv4, {LDAP_TABLE_NAME}.ldap_server, {HOSTS_TABLE_NAME}.scan_date, {HOSTS_TABLE_NAME}.port FROM {HOSTS_TABLE_NAME} INNER JOIN {LDAP_TABLE_NAME} ON {HOSTS_TABLE_NAME}.id={LDAP_TABLE_NAME}.id AND {HOSTS_TABLE_NAME}.scan_date={LDAP_TABLE_NAME}.scan_date AND {HOSTS_TABLE_NAME}.port={LDAP_TABLE_NAME}.port WHERE isIPAddressInRange({HOSTS_TABLE_NAME}.ipv4, '{ip_prefix}') AND {LDAP_TABLE_NAME}.ldap_server=1")
    ldap_dict = ldap_pdf.to_dict(orient="records")
    result2 = merge_list_dict(result1, ldap_dict)

    starttls_ldap_pdf = client.query_df(f"SELECT {HOSTS_TABLE_NAME}.ipv4, {STARTTLS_TABLE_NAME}.ldap_server, {HOSTS_TABLE_NAME}.scan_date, {HOSTS_TABLE_NAME}.port FROM {HOSTS_TABLE_NAME} INNER JOIN {STARTTLS_TABLE_NAME} ON {HOSTS_TABLE_NAME}.id={STARTTLS_TABLE_NAME}.id AND {HOSTS_TABLE_NAME}.scan_date={STARTTLS_TABLE_NAME}.scan_date AND {HOSTS_TABLE_NAME}.port={STARTTLS_TABLE_NAME}.port WHERE isIPAddressInRange({HOSTS_TABLE_NAME}.ipv4, '{ip_prefix}') AND {STARTTLS_TABLE_NAME}.ldap_server=1")
    starttls_dict = starttls_ldap_pdf.to_dict(orient="records")
    result = merge_list_dict(result2, starttls_dict)

    return result


def decode_cert(pdf):
    pem = pdf["cert"]
    try:
        cert = x509.load_pem_x509_certificate(str.encode(pem), default_backend())
    except ValueError:
        # the certificate contains bytes that cannot be interpreted. Probably invalid cert
        # https://github.com/pyca/cryptography/issues/6804
        return pdf

    subject_rdns = []
    issuer_rdns = []
    try:
        issuer_rdns = [rdn.rfc4514_string() for rdn in cert.issuer.rdns]
        subject_rdns = [rdn.rfc4514_string() for rdn in cert.subject.rdns]
    except ValueError:
        # the certificate contains bytes that cannot be interpreted. Probably invalid cert
        # https://github.com/pyca/cryptography/issues/6804
        pass

    not_valid_after = None
    try:
        if cert.not_valid_after > datetime.min:
            not_valid_after = cert.not_valid_after
    except ValueError:
        # ValueError: year 0 is out of range
        pass
    not_valid_before = None
    try:
        if cert.not_valid_before > datetime.min:
            not_valid_before = cert.not_valid_before
    except ValueError:
        # ValueError: year 0 is out of range
        pass

    pdf["subject"] = subject_rdns
    pdf["issuer"] = issuer_rdns
    pdf["not_valid_after"] = not_valid_after
    pdf["not_valid_before"] = not_valid_before
    return pdf


def merge_list_dict(data1, data2):
    for i in data1:
        for j in data2:
            if i["ipv4"] == j["ipv4"] and i["port"] == j["port"]:  # and i["scan_date"] == j["scan_date"]:
                i.update(j)
    return data1


def _get_tcp_layer_info_spark(ip_prefix: str, zmap_df):
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


def _get_app_layer_info_spark(ip_prefix: str, goscanner_df):
    goscanner_df = goscanner_df.withColumn("is_ip_in_prefix",
                                           is_ip_in_prefix_udf(psf.col("ipv4"),
                                                               psf.lit(ip_prefix)))
    goscanner_dict = goscanner_df.filter(
        psf.col("is_ip_in_prefix") == True
    ).drop("is_ip_in_prefix").toPandas().to_dict(orient="records")
    return goscanner_dict
