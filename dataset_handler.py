__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from datetime import datetime
from glob import glob

import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import pyspark.sql.functions as psf
import pyspark.sql.types as pst
from pyspark.storagelevel import StorageLevel

from ip_as import IPASnPrefix
from spark_session import get_spark_instance, clean_spark

dataset_pyasn = None  # {"YYYYMMDD": IPASnPrefix object}

spark = None
sc = None


def init_dataset():
    global spark, sc
    spark, sc = get_spark_instance()


def load_dataset() -> None:
    print("Loading datasets...")
    dataset_scanning = _load_zmap_dataset()
    dataset_scanning.update(_load_goscanner_dataset())
    #dataset_scanning.update(_load_pyasn_dataset())  # future use
    return dataset_scanning


def _load_zmap_dataset():
    dataset_scanning = {}
    print("Loading ZMap dataset...")

    zmap_dir = f"research_data/catrin/measurements/tool=zmap/dataset=default"
    dataset_scanning["zmap"] = _load_spark_zmap(zmap_dir)
    dataset_scanning["zmap"].persist(StorageLevel.MEMORY_AND_DISK)
    return dataset_scanning

def _load_spark_zmap(zmap_dir: str):
    df = spark.read.option("header", "true"
                    ).option("inferSchema", "true"
                    ).option("basePath", zmap_dir
                    ).csv(zmap_dir)

    df = df.withColumn("scan_date", scan_date_udf(psf.col("year"), psf.col("month"), psf.col("day")))
    return df.select(psf.col("saddr").alias("ipv4"), "port", "scan_date")


def _scan_date(year, month, day):
    return f"{year}{month:02}{day:02}"


scan_date_udf = psf.udf(_scan_date, pst.StringType())


def _load_pandas_csv_file(port_date_list: list, zmap_dir: str):
    # not used/not working
    pdfs = pd.DataFrame()
    for entry in port_date_list:
        port = entry["port"]
        scan_date = str(entry["scan_date"])
        timestamp_path = _get_timestamp_path(scan_date)
        file_path = glob(f"{zmap_dir}/port={port}/{timestamp_path}/*.csv")
        pdf = pd.read_csv(file_path)
        pdf["port"] = port
        pdf["scan_date"] = scan_date
        pdfs = pd.concat([pdfs, pdf])

    return pdfs


def _get_timestamp_path(scan_date: str) -> str:
    timestamp = datetime.strptime(scan_date, "%Y%m%d")
    return f"year={timestamp.year}/month={timestamp.month:02}/day={timestamp.day:02}"


def _load_goscanner_dataset():
    print("Loading Goscanner dataset...")
    dataset_scanning = {}

    goscanner_dir_fmt = "research_data/catrin/measurements/tool=goscanner/format=raw/port={port}"
    dataset_scanning["goscanner"] = _load_goscanner(goscanner_dir_fmt)
    dataset_scanning["goscanner"].persist(StorageLevel.MEMORY_AND_DISK)
    return dataset_scanning


def _load_goscanner(goscanner_dir_fmt: str):
    # this function depends on the fact that goscanner data hold only one snapshot
    # otherwise the date will be lost
    def _load_data(port, goscanner_dir_fmt):
        base_path = goscanner_dir_fmt.format(port=port)
        df = spark.read.option("header", "true"
                    ).option("lineSep", "\n"
                    ).option("quote", "\""
                    ).option("escape", "\""
                    ).option("inferSchema", "true"
                    ).option("basePath", base_path
                    ).csv(base_path)
        return df

    def _load_certs_data(port, certs_dir_fmt):
        certs_base_path = certs_dir_fmt.format(port=port)
        certs_df = spark.read.option("header", "true"
                            ).option("multiline", "true"
                            ).option("wholeFile", "true"
                            ).option("inferSchema", "true"
                            ).option("basePath", certs_base_path
                            ).csv(certs_base_path)
        return certs_df

    hosts_dir_fmt = goscanner_dir_fmt + "/scan=tcp/result=hosts"
    starttls_dir_fmt = goscanner_dir_fmt + "/scan=starttls_ldap/result=starttls_ldap"
    ldap_dir_fmt = goscanner_dir_fmt + "/scan=ldap/result=ldap"
    certs_dir_fmt = goscanner_dir_fmt + "/scan=tls/result=certs"

    def _combine_dataset(port):
        # we would lose the date of the scan if we have more than one snapshot
        # because of the select statements below
        hosts_df = _load_data(port, hosts_dir_fmt)
        hosts_df = hosts_df.select(psf.col("id").alias("host_id"),
                                   psf.col("ip").alias("ipv4"),
                                   "server_name", "protocol", "cipher",
                                   "resultString",
                                   psf.col("cert_id").alias("hosts_cert_id"),
                                   "cert_hash", "pub_key_hash",
                                   "year", "month", "day")

        certs_df = _load_certs_data(port, certs_dir_fmt)
        certs_df = certs_df.select(psf.col("id").alias("cert_id"), "cert")

        ldap_df = None
        if port == 636:
            ldap_df = _load_data(port, ldap_dir_fmt)
        else:  # 389
            ldap_df = _load_data(port, starttls_dir_fmt)
        ldap_df = ldap_df.select(psf.col("id").alias("ldap_id"), "ldap_server")

        ldap_hosts_df = hosts_df.join(ldap_df, ldap_df.ldap_id == hosts_df.host_id, "inner").filter(psf.col("ldap_id").isNotNull()).drop("ldap_id", "host_id")

        ldap_hosts_cert_df = ldap_hosts_df.join(certs_df, ldap_hosts_df.hosts_cert_id == certs_df.cert_id, "inner").drop("hosts_cert_id", "cert_id")

        ldap_hosts_cert_df = ldap_hosts_cert_df.withColumn("port", psf.lit(port).cast(pst.IntegerType()))
        ldap_hosts_cert_df = ldap_hosts_cert_df.withColumn("scan_date", scan_date_udf(psf.col("year"), psf.col("month"), psf.col("day"))).drop("year", "month", "day")

        ldap_hosts_cert_df = ldap_hosts_cert_df.withColumn("decoded_cert", decode_cert_udf(psf.col("cert"))).drop("cert")
        return ldap_hosts_cert_df

    goscanner_df = _combine_dataset(389).unionByName(_combine_dataset(636))

    return goscanner_df.select(
        "ipv4", "port", "scan_date", "ldap_server",
        "server_name", "protocol", "cipher",
        "resultString", "cert_hash", "pub_key_hash",
        "decoded_cert.issuer", "decoded_cert.subject",
        "decoded_cert.not_valid_before", "decoded_cert.not_valid_after"
    )


def get_x509_fields(pem: str):
    try:
        cert = x509.load_pem_x509_certificate(str.encode(pem), default_backend())
    except ValueError:
        # the certificate contains bytes that cannot be interpreted. Probably invalid cert
        # https://github.com/pyca/cryptography/issues/6804
        return 4 * [None]  # CHANGE HERE IN CASE ADDITIONAL RETURN PARAMETER

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

    return (subject_rdns,
            issuer_rdns,
            not_valid_after,
            not_valid_before,
           )


pem_decoded_schema = pst.StructType([pst.StructField("subject", pst.ArrayType(pst.StringType()), True),
                                     pst.StructField("issuer", pst.ArrayType(pst.StringType()), True),
                                     pst.StructField("not_valid_after", pst.TimestampType(), True),
                                     pst.StructField("not_valid_before", pst.TimestampType(), True),
                                    ])


decode_cert_udf = psf.udf(get_x509_fields, pem_decoded_schema)


def _load_pyasn_dataset():
    dataset_pyasn = {}

    zmap_port_date_pdf = pd.read_csv("zmap-port-date.csv", header=None)
    zmap_port_date_pdf.columns = ["port", "scan_date"]
    port_date_list = zmap_port_date_pdf.to_dict(orient="records")
    for entry in port_date_list:
        scan_date = str(entry["scan_date"])
        if dataset_pyasn.get(scan_date) is None:
            dataset_pyasn[scan_date] = IPASnPrefix(scan_date)
    goscanner_port_date_pdf = pd.read_csv("goscanner-port-date.csv", header=None)
    goscanner_port_date_pdf.columns = ["port", "scan", "result", "scan_date"]
    port_date_list = goscanner_port_date_pdf.to_dict(orient="records")
    for entry in port_date_list:
        scan_date = str(entry["scan_date"])
        if dataset_pyasn.get(scan_date) is None:
            dataset_pyasn[scan_date] = IPASnPrefix(scan_date)

    return dataset_pyasn


def delete_dataset(dataset_scanning: dict):
    clean_spark(spark, sc)
    del dataset_scanning
    print("Dataset cleaned up.")
