__author__ = "Gustavo Luvizotto Cesar"

from datetime import datetime

import clickhouse_connect as chc
import credentials_clickhouse as c
import pandas as pd

ZMAP_TABLE_NAME = "zmap"
HOSTS_TABLE_NAME = "hosts"
STARTTLS_TABLE_NAME = "starttls_ldap"
LDAP_TABLE_NAME = "ldap"
CERTS_TABLE_NAME = "certs"
ALERTS_TABLE_NAME = "alerts"


def main():
    client = chc.get_client(host=c.host, port=c.port, username=c.default_user, password=c.default_password)

    load_zmap(client)

    load_goscanner(client)

    prepare_alerts(client)


def load_zmap(client):
    print("Loading ZMap dataset...")

    zmap_dir_fmt = "catrin/measurements/tool=zmap/dataset=default/port={port}/year={year}/month={month:02}/day={day:02}"

    _ = client.query(f"CREATE TABLE {ZMAP_TABLE_NAME} (`ipv4` String, port UInt16, scan_date DateTime('Etc/UTC')) ENGINE = MergeTree ORDER BY (ipv4, port, scan_date)")

    zmap_port_date_pdf = pd.read_csv("zmap-port-date.csv", header=None)
    zmap_port_date_pdf.columns = ["port", "scan_date"]
    port_date_list = zmap_port_date_pdf.to_dict(orient="records")
    for entry in port_date_list:
        port = entry["port"]
        scan_date = str(entry["scan_date"])
        ts = datetime.strptime(scan_date, "%Y%m%d")
        zmap_dir = zmap_dir_fmt.format(port=port, year=ts.year, month=ts.month, day=ts.day)
        _ = client.query(f"INSERT INTO {ZMAP_TABLE_NAME} SELECT saddr, {port} AS port, formatDateTime(toDate('{scan_date}'), '%F', 'Etc/UTC') as scan_date FROM s3('http://localhost:8080/{zmap_dir}/*.csv', '{c.aws_access_key_id}', '{c.aws_secret_access_key}', 'CSVWithNames')")
        print("loaded", scan_date)


def load_goscanner(client):
    print("Loading Goscanner dataset...")

    goscanner_dir_fmt = "catrin/measurements/tool=goscanner/format=raw/port={port}/scan={scan}/result={result}/year={year}/month={month:02}/day={day:02}"

    # create tables
    _ = client.query(f"CREATE TABLE {HOSTS_TABLE_NAME} (id UInt32, ipv4 String, port UInt16, server_name Nullable(String), synStart Int64, synEnd Int64, scanEnd Nullable(Int64), protocol Nullable(UInt16), cipher Nullable(String), resultString String, error_data Nullable(String), cert_id Nullable(UInt64), cert_hash Nullable(String), pub_key_hash Nullable(String), cert_valid UInt8, tls_alerts_send Array(Int32), peer_certificates Array(Int32), tls_alerts_received Array(Int32), client_hello Nullable(String), scan_date DateTime('Etc/UTC')) ENGINE = MergeTree ORDER BY (ipv4, port, scan_date)")

    _ = client.query(f"CREATE TABLE {CERTS_TABLE_NAME} (id UInt32, cert String, system_cert_store UInt8, port UInt16, scan_date DateTime('Etc/UTC')) ENGINE = MergeTree ORDER BY (id, port, scan_date)")

    _ = client.query(f"CREATE TABLE {LDAP_TABLE_NAME} (id UInt32, ldap_server UInt8, result_code Int32, matched_dn Nullable(String), diagnostic_message Nullable(String), error_data Nullable(String), responded_with_notice_of_disconnection Int32, unbind_response Nullable(String), unbind_error Nullable(String), port UInt16, scan_date DateTime('Etc/UTC')) ENGINE = MergeTree ORDER BY (id, port, scan_date)")

    _ = client.query(f"CREATE TABLE {STARTTLS_TABLE_NAME} (id UInt32, starttls UInt8, ldap_server UInt8, responded_to_starttls UInt8, result_code Int32, matched_dn Nullable(String), diagnostic_message Nullable(String), error_data Nullable(String), port UInt16, scan_date DateTime('Etc/UTC')) ENGINE = MergeTree ORDER BY (id, port, scan_date)")

    # load into the tables
    goscanner_port_date_pdf = pd.read_csv("goscanner-port-date.csv", header=None)
    goscanner_port_date_pdf.columns = ["port", "scan", "result", "scan_date"]
    port_date_list = goscanner_port_date_pdf.to_dict(orient="records")
    for entry in port_date_list:
        port = entry["port"]
        scan = entry["scan"]
        result = entry["result"]
        scan_date = str(entry["scan_date"])
        ts = datetime.strptime(scan_date, "%Y%m%d")
        goscanner_dir = goscanner_dir_fmt.format(port=port, scan=scan,
                                                 result=result, year=ts.year,
                                                 month=ts.month, day=ts.day)

        if result == "hosts":
            _insert_into_hosts(client, goscanner_dir, scan_date)
            print("loaded", scan_date, port, result, scan)
        if result == "certs":
            _insert_into_certs(client, goscanner_dir, scan_date, port)
            print("loaded", scan_date, port, result, scan)

        if port == 636:
            if result == "ldap":
                _insert_into_ldap(client, goscanner_dir, scan_date, port)
                print("loaded", scan_date, port, result, scan)
        else:  # port == 389
            if result == "starttls_ldap":
                _insert_into_starttls_ldap(client, goscanner_dir, scan_date, port)
                print("loaded", scan_date, port, result, scan)


def _insert_into_hosts(client, goscanner_dir, scan_date):
    _ = client.query(f"INSERT INTO {HOSTS_TABLE_NAME} SELECT id,ip,port,server_name,synStart,synEnd,scanEnd,protocol,cipher,resultString,error_data,cert_id,cert_hash,pub_key_hash,cert_valid,tls_alerts_send,peer_certificates,tls_alerts_received,client_hello,formatDateTime(toDate('{scan_date}'), '%F', 'Etc/UTC') as scan_date FROM s3('http://localhost:8080/{goscanner_dir}/*.csv', '{c.aws_access_key_id}', '{c.aws_secret_access_key}', 'CSVWithNames')")


def _insert_into_certs(client, goscanner_dir, scan_date, port):
    _ = client.query(f"INSERT INTO {CERTS_TABLE_NAME} SELECT id,cert,system_cert_store, {port} AS port, formatDateTime(toDate('{scan_date}'), '%F', 'Etc/UTC') as scan_date FROM s3('http://localhost:8080/{goscanner_dir}/*.csv', '{c.aws_access_key_id}', '{c.aws_secret_access_key}', 'CSVWithNames')")


def _insert_into_ldap(client, goscanner_dir, scan_date, port):
    _ = client.query(f"INSERT INTO {LDAP_TABLE_NAME} SELECT id,ldap_server,result_code,matched_dn,diagnostic_message,error_data,responded_with_notice_of_disconnection,unbind_response,unbind_error, {port} as port, formatDateTime(toDate('{scan_date}'), '%F', 'Etc/UTC') as scan_date FROM s3('http://localhost:8080/{goscanner_dir}/*.csv', '{c.aws_access_key_id}', '{c.aws_secret_access_key}', 'CSVWithNames')")


def _insert_into_starttls_ldap(client, goscanner_dir, scan_date, port):
    _ = client.query(f"INSERT INTO {STARTTLS_TABLE_NAME} SELECT id,starttls,ldap_server,responded_to_starttls,result_code,matched_dn,diagnostic_message,error_data, {port} as port, formatDateTime(toDate('{scan_date}'), '%F', 'Etc/UTC') as scan_date FROM s3('http://localhost:8080/{goscanner_dir}/*.csv', '{c.aws_access_key_id}', '{c.aws_secret_access_key}', 'CSVWithNames')")

def prepare_alerts(client):
    # create table
    _ = client.query(f"CREATE TABLE {ALERTS_TABLE_NAME} (id String, uid UInt32, attacker String, attacker_port UInt16, sid UInt16, msg String, datetime DateTime('Etc/UTC')) ENGINE = MergeTree ORDER BY (attacker, datetime)")
    

if __name__ == "__main__":
    main()
