import pandas as pd
from glob import glob
import read_p4_data as rpd


KEY_AS_PATH = 'as_path'
KEY_ROV_SCORES = 'rov_of_each_asn'


def get_as_data():
    as_data = _get_critical_ases_data()
    as_data.update(_get_mocked_ases_data())
    return as_data

def _get_critical_ases_data() -> dict:
    csv_files = [
        "/flasksite_data/abn.csv",
        "/flasksite_data/eneco.csv",
        "/flasksite_data/ing.csv"
    ]

    as_data = {}
    for csv_file in csv_files:
        pdf = pd.read_csv(csv_file)
        for _, row in pdf.iterrows():
            asn_list_str = row['as_path']
            rov_of_each_asn_list_str = row['rov_of_each_asn']
            for asn, rov_score in zip(asn_list_str.split(','), rov_of_each_asn_list_str.split(',')):
                asn = int(asn.strip())
                rov_score = 1 if rov_score.strip() == '100.0' else 0
                as_data[asn] = {
                    'is_mocked': False,
                    'as_rov_score': rov_score
                }
    return as_data

def _get_mocked_ases_data():
    bin_path = "/research_data/*.bin"
    p4_data = rpd.read_p4_data(bin_path)
    return p4_data

if __name__ == "__main__":
    as_data = get_as_data()
    print(as_data)
