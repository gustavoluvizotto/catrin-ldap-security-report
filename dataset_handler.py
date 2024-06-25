__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from datetime import datetime
from glob import glob

import pandas as pd


dataset_scanning = {}
dataset_pyasn = {}  # {"YYYYMMDD": IPASnPrefix object}


def init_dataset():
    global dataset_scanning
    dataset_scanning = {
        "zmap": {
            80: {
                "dataset": None,
                "scan_date": None
                },
        },
        "goscanner": {
            389: {
                "scan_date": None,
                "tcp": {
                    "hosts": None
                },
                "tls": {
                    "cert_chain": None,
                    "certs": None,
                    "tls_verbose": None
                },
                "ldap_metadata": {
                    "ldap_root_dse": None
                },
                "starttls_ldap": {
                    "starttls_ldap": None
                },
                "ldap": {
                    "ldap": None
                }
            },
        }
    }


def load_dataset() -> None:
    print("Loading datasets... ")
    _load_zmap_dataset()
    _load_goscanner_dataset()


def _load_zmap_dataset():
    global dataset_scanning
    print("Loading ZMap dataset...")
    zmap_port_date_pdf = pd.read_csv("zmap-port-date.csv", header=None)
    zmap_port_date_pdf.columns = ["port", "scan_date"]
    port_date_list = zmap_port_date_pdf.to_dict(orient="records")
    for port_date in port_date_list:
        port = port_date["port"]
        timestamp = datetime.strptime(str(port_date["scan_date"]), "%Y%m%d")
        timestamp_path = f"year={timestamp.year}/month={timestamp.month:02}/day={timestamp.day:02}"
        zmap_file_path = glob(f"research_data/catrin/measurements/tool=zmap/dataset=default/port={port}/{timestamp_path}/*.csv")
        dataset_scanning["zmap"][port] = {
            "dataset": pd.read_csv(zmap_file_path[0]),
            "scan_date": port_date["scan_date"]
        }
        print("loaded timestamp", timestamp)


def _load_goscanner_dataset():
    global dataset_scanning
    print("Loading Goscanner dataset...")
    goscanner_port_date_pdf = pd.read_csv("goscanner-port-date.csv", header=None)
    goscanner_port_date_pdf.columns = ["port", "scan", "result", "scan_date"]
    port_date_list = goscanner_port_date_pdf.to_dict(orient="records")
    for port_date in port_date_list:
        port = port_date["port"]
        timestamp = datetime.strptime(str(port_date["scan_date"]), "%Y%m%d")
        timestamp_path = f"year={timestamp.year}/month={timestamp.month:02}/day={timestamp.day:02}"
        goscanner_file_path = glob(f"research_data/catrin/measurements/tool=goscanner/dataset=default/port={port}/{timestamp_path}/*.csv")
        dataset_scanning["goscanner"][port] = {
            "dataset": pd.read_csv(goscanner_file_path[0]),
            "scan_date": port_date["scan_date"]
        }
        print("loaded timestamp", timestamp)


def delete_dataset():
    global dataset_scanning
    del dataset_scanning
