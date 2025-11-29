import struct
from glob import glob


KIND = 114  # 0x72 ALWAYS

# just a few country codes
US = 1
CA = 2
MX = 3
NL = 4
DE = 5
IT = 6
FR = 7
GB = 8
CN = 9
RU = 10
IN = 11
JP = 12
KR = 13
AU = 14
BR = 15
ZA = 16
NP = 17
TR = 18
AT = 19


# https://www.caida.org/catalog/datasets/as-classification/
TRANSIT_AS = 1  # this includes IXPs, Tier1, Tier2, Tier3
CDN_AS = 2
ENTERPRISE_AS = 3
#STUB_AS
#MULTIHOMED_AS
#TIER1_AS
#TIER2_AS
#TIER3_AS

# ROV score 0 or 1 (1 for 100% ROV, otherwise 0)
# MANRS member 0 or 1 (not participating or participating in MANRS)
# Middlebox risk levels
# nr_mbs == 0 then LOW RISK
LOW_RISK = 0  # <=30%
MILD_RISK = 1  # <=50%
MODERATE_RISK = 2  # <=75%
HIGH_RISK = 3  # >75%

def read_p4_data(filepath):
    # Define the struct format (little endian '<' or big endian '>')
    # '<' = little-endian, standard size (no padding)
    fmt = '<BBIBB'

    record_size = struct.calcsize(fmt)

    bin_files = glob(filepath)

    p4_data = dict({})
    for bin_file in bin_files:
        with open(bin_file, "rb") as f:
            data = f.read(record_size)

        # Unpack into a tuple
        _, _, as_number, as_country, last_byte = struct.unpack(fmt, data)

        as_type                   = (last_byte >> 0) & 0x07  # bits 2..0
        as_rov_score              = (last_byte >> 3) & 0x01  # bit 3
        as_manrs_member           = (last_byte >> 4) & 0x01  # bit 4
        middlebox_avg_risk_level  = (last_byte >> 5) & 0x03  # bits 6..5
        as_ldap_risk              = (last_byte >> 7) & 0x01  # bit 7
        p4_data[as_number] = {
            #"kind": kind,
            #"length": length,
            "as_country": as_country,
            "as_type": as_type,
            "as_rov_score": as_rov_score,
            "as_manrs_member": as_manrs_member,
            "middlebox_avg_risk_level": middlebox_avg_risk_level,
            "as_ldap_risk": as_ldap_risk,
            "is_mocked": True
        }
    return p4_data


def print_p4_binaries_json(p4_json):
    for bin_file, data in p4_json.items():
        print(f"ASN: {bin_file}")
        for key, value in data.items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    bin_filepath = "../research_data/*.bin"
    p4_json = read_p4_data(bin_filepath)
    print_p4_binaries_json(p4_json)
