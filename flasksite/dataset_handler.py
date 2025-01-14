__author__ = "Gustavo Luvizotto Cesar"

import pandas as pd

from ip_as import IPASnPrefix


dataset_pyasn = None  # {"YYYYMMDD": IPASnPrefix object}


def load_dataset() -> None:
    print("Loading datasets...")
    dataset_scanning = _load_pyasn_dataset()  # future use
    return dataset_scanning


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
