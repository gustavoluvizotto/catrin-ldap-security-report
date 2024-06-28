__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from datetime import datetime, timezone

import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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
        if cert.not_valid_after_utc <= datetime.max.replace(tzinfo=timezone.utc):
            not_valid_after = cert.not_valid_after_utc
    except ValueError:
        # ValueError: year 0 is out of range
        pass
    not_valid_before = None
    try:
        if cert.not_valid_before_utc >= datetime.min.replace(tzinfo=timezone.utc):
            not_valid_before = cert.not_valid_before_utc
    except ValueError:
        # ValueError: year 0 is out of range
        pass

    pdf["subject"] = subject_rdns
    pdf["issuer"] = issuer_rdns
    pdf["not_valid_after"] = not_valid_after
    pdf["not_valid_before"] = not_valid_before
    return pdf


tls_version_str_dict = {
    int("0x0301", 16): "TLSv1.0",
    int("0x0302", 16): "TLSv1.1",
    int("0x0303", 16): "TLSv1.2",
    int("0x0304", 16): "TLSv1.3",
    int("0x0300", 16): "SSLv3"
}


def tls_version_to_string(version_number: int) -> str:
    return tls_version_str_dict.get(version_number, str(version_number))


def convert_cipher(x):
    try:
        parts = [int(part, 16) for part in x.split(",")]
    except ValueError:
        # to cover reserved values like 0x00,0x1C-1D
        return None
    cipher = parts[0] << 8
    cipher |= parts[1]
    return hex(cipher)[2:]


# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
tls_parameters_pdf = pd.read_csv("tls-parameters-4.csv")
tls_parameters_pdf["Cipher"] = tls_parameters_pdf["Value"].apply(convert_cipher)
tls_parameters_pdf["DTLS-OK"] = tls_parameters_pdf["DTLS-OK"].apply(lambda x: str(x))
tls_parameters_pdf["Recommended"] = tls_parameters_pdf["Recommended"].apply(lambda x: str(x))
tls_parameters_pdf["Reference"] = tls_parameters_pdf["Reference"].apply(lambda x: str(x))
tls_parameter_dict = tls_parameters_pdf[["Cipher", "Description"]].set_index("Cipher").to_dict()["Description"]


def cipher_to_description(cipher: str) -> str:
    return tls_parameter_dict.get(cipher, "Unknown")


def merge_list_dict(data1, data2):
    for i in data1:
        for j in data2:
            if i["ipv4"] == j["ipv4"] and i["port"] == j["port"]:  # and i["scan_date"] == j["scan_date"]:
                i.update(j)
    return data1
