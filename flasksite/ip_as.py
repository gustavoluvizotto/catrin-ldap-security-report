__author__ = "Gustavo Luvizotto Cesar"

import os
import glob
from datetime import datetime

import pyasn


class IPASnPrefix(object):

    def __init__(self, date_str: str):
        # Initialize module and load IP to ASN database
        p = GetPyAsnDataset()
        pyasn_dat = p.get_latest_file(date_str)
        self.asndb = pyasn.pyasn(pyasn_dat)

    def get_asn_from_ip(self, ip: str) -> int:
        """
        asd
        :param ip:
        :return:
        """
        return self.asndb.lookup(ip)[0]

    def get_prefix_from_ip(self, ip: str) -> str:
        return self.asndb.lookup(ip)[-1]

    def get_prefixes_from_asn(self, asn: int):
        """
        asd
        :param asn:
        :return:
        """
        return self.asndb.get_as_prefixes(asn)


class GetPyAsnDataset(object):
    def get_latest_file(self, date_str: str) -> str:
        return self._get_latest_file(date_str, "research_data/pyasn/*.dat")

    def _get_latest_file(self, date_str, pattern):
        dat_files = glob.glob(pattern)

        dat_files.sort(reverse=True)
        found_file = None
        for dat_file in dat_files:
            filename = os.path.basename(dat_file)
            actual_date_str = self._get_date_from_filename(filename)
            dat_file_date = datetime.strptime(actual_date_str, "%Y%m%d")
            desired_date = datetime.strptime(date_str, "%Y%m%d")
            if dat_file_date <= desired_date:
                found_file = dat_file
                break
        assert found_file is not None, "Could not find the closest file you were looking for"
        return found_file

    def _get_date_from_filename(self, filename: str) -> str:
        filename_no_extension = os.path.splitext(filename)[0]
        return filename_no_extension.split("_")[-1]
