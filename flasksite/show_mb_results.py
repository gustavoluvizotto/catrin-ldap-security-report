import json
import requests
import time  # to avoid rate limit
from middlebox_data import address_map, show_mb_results


#TODO: This part is not working currently
def get_cve_severity(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            impact = data.get("result", {}).get("CVE_Items", [])[0].get("impact", {})
            base_score = None
            if "baseMetricV3" in impact:
                severity = impact["baseMetricV3"]["cvssV3"]["baseSeverity"]
            elif "baseMetricV2" in impact:
                severity = impact["baseMetricV2"]["severity"]
            else:
                severity = "UNKNOWN"
            return severity.upper()
        else:
            return "UNKNOWN"
    except Exception as e:
        return "UNKNOWN"

def calculate_middlebox_score(ip, middlebox):

    #TODO: Update the weights and scoring logic based on the latest requirements
    MODIFICATION_WEIGHTS = {
        "TCP MP Capable Removed": 5,
        "TCP NOP Added": 3,
        "TCP Timestamp TSVal Modified": 3,
        "TCP Timestamp Tsecr Modified": 3,
        "TCP Timestamp Removal": 5,
        "TCP Urgent Pointer/Receiver Window Modified": 3,
        "TCP Data Offset Modified": 3,
        "TCP Sack Permitted Removal": 5,
        "IP Total Length Modified": 5,
        "TCP Sequence Number Modified": 5,
        "TCP Data Offset Modified": 3, 
        "TCP MSS Data Modified": 3,
        "IPID/TSval/TSecr/RW or UP Modified": 2,
        "IPID/TSval/RW or UP Modififed": 2,
        "TSecr/RW or UP Modififed": 2
    }

    PORT_WEIGHTS = {
        80: 2,   # HTTP
        443: 2,  # HTTPS
        389: 3,  # LDAP
        264: 3,  # Checkpoint Topology
        4443: 3, # Alternate HTTPS
        500: 3,  # IKE
        2000: 2  # Mikrotik Bandwidth
    }

    HIGH_RISK_PORTS = {
    21,    # FTP
    22,    # SSH 
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    69,    # TFTP
    110,   # POP3
    111,   # RPCbind
    135,   # MS RPC
    137, 138, 139,  # NetBIOS
    143,   # IMAP
    161, 162,  # SNMP
    389,   # LDAP
    445,   # SMB
    512, 513, 514,  # r-services
    873,   # rsync
    1433, 1434,  # MS SQL Server
    1900,  # SSDP
    2049,  # NFS
    2375, 2376,  # Docker
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080, 8888  # Dev/admin interfaces
    }


    CVE_WEIGHTS = {
        "low": 3,
        "medium": 5,
        "high": 7
    }

    VENDOR_WEIGHTS = {
        "Palo Alto Networks": 5,
        "pfSense": 3,
        "Fortinet": 5,
        "Check Point": 5,
        "Mikrotik": 1,
        "Cisco": 5,
        "Juniper": 5,
        "Huawei": 5,
        "SonicWall": 5,
        "Ruijie": 5,
    }   

    GEOLOCATION_WEIGHTS = {
        "high_risk_as": 5,
        "unusual_location": 3
    }

    score = 0

    # 1. Detected Modifications
    modifications = middlebox.get("Detected Modifications", [])
    for mod in modifications:
        score += MODIFICATION_WEIGHTS.get(mod, 3)

    # 2. Open Ports
    open_ports = middlebox.get("Open Ports", [])
    for port_entry in open_ports:
        port = port_entry.get("Port Number")
        score += PORT_WEIGHTS.get(port, 2)
        if port in HIGH_RISK_PORTS:
            score += 5

    # 3. Known Vulnerabilities
    vulnerabilities = middlebox.get("Vulnerabilities", [])
    for cve in vulnerabilities:
        if "CVE" in cve:
            severity = get_cve_severity(cve)
            if severity == "CRITICAL" or severity == "HIGH":
                score += CVE_WEIGHTS["high"]
            elif severity == "MEDIUM":
                score += CVE_WEIGHTS["medium"]
            elif severity == "LOW":
                score += CVE_WEIGHTS["low"]
            else:
                score += 2  # unknown severity
            time.sleep(0.6)  # to stay within NVD rate limit

    # 4. Vendor Information
    vendor = middlebox.get("Vendor Information", {}).get("Vendor", "Unknown")
    score += VENDOR_WEIGHTS.get(vendor, 3)

    # 5. Geolocation & AS Info
    as_name = middlebox.get("AS Information", {}).get("AS Name", "")
    risky_asns = {"Known Risky AS", "Verizon Business EMEA", "Cogent Communications"}
    if as_name in risky_asns:
        score += GEOLOCATION_WEIGHTS["high_risk_as"]

    country = middlebox.get("Geolocation Information", {}).get("Country", "")
    if country not in ["United Kingdom", "United States of America"]:
        score += GEOLOCATION_WEIGHTS["unusual_location"]

    # Cap score at 100
    score = min(score, 100)

    if score <= 30:
        risk_level = "Low Risk"
    elif score <= 50:
        risk_level = "Mild Risk"
    elif score <= 75:
        risk_level = "Moderate Risk"
    else:
        risk_level = "High Risk"

    return {"ip": ip, "score": score, "risk_level": risk_level}

"""
def process_all_middleboxes():
    all_results = []

    for asn, ip_list in address_map.items():
        print(f"Processing {asn}...")
        for ip in ip_list:
            if "could not detect" in ip.lower():
                continue  # skip placeholder entries
            middlebox = show_mb_results(ip)
            if "error" not in middlebox:
                result = calculate_middlebox_score(ip, middlebox)
                result["asn"] = asn
                all_results.append(result)

    return all_results

# Run
results = process_all_middleboxes()
print(json.dumps(results, indent=2))
"""

# Internal cache of all results
_processed_data = {}

def process_all_middleboxes():
    global _processed_data
    _processed_data = {}  # Reset cache

    for asn, ip_list in address_map.items():
        mb_list = []
        for ip in ip_list:
            if "could not detect" in ip.lower():
                continue
            middlebox = show_mb_results(ip)
            if "error" not in middlebox:
                result = calculate_middlebox_score(ip, middlebox)
                result["asn"] = asn
                mb_list.append(result)
        if mb_list:
            _processed_data[asn] = mb_list

def get_middlebox_by_asn(asn):
    return _processed_data.get(asn, [])

def get_middlebox_by_ip(ip):
    for asn, mb_list in _processed_data.items():
        for mb in mb_list:
            if mb["ip"] == ip:
                return mb
    return {"error": "IP not found"}
 