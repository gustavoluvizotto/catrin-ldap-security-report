def get_middlebox_ips(address):
    address_map = {
        '129.2.248.132': ['128.8.144.162'],
        '92.27.213.175': ['80.95.199.213'],
        '132.235.51.88': ['132.235.231.170', '132.235.185.140'],
        '54.205.164.113': ['Could not detect a middlebox on the path to the target.']
    }
    return address_map.get(address, [])

def show_mb_results(ip):
    ip_data = {
        '128.8.144.162': {
            "detected_modifications": [
                "TCP Hash Modified",
                "Complete Hash Modified",
                "TCP MP Capable Removed",
                "TCP NOP Added"
            ],
            "geolocation_information": {
                "country": "United States of America [US]",
                "region": "Maryland",
                "city": "College Park",
                "coordinates": "38.992080, -76.952830 (38°59'31\"N 76°57'10\"W)"
            },
            "as_information": {
                "asn": "AS27",
                "as_name": "UMDNET",
                "organization": "University of Maryland",
                "total_ipv4_prefixes": 7,
                "total_ipv4_address": 139776
            },
            "vendor_information": "Vendor could not be identified",
            "security_evaluation": {
                "open_ports": [
                    {"port_number": 179, "service_name": "BGP"}
                ],
                "vulnerabilities": "There is no vulnerability for this middlebox."
            }
        },
        '80.95.199.213': {
            "detected_modifications": [
                "IP Hash Modified",
                "TCP Hash Modified",
                "Complete Hash Modified",
                "TCP MP Capable Removed",
                "TCP NOP Added"
            ],
            "geolocation_information": {
                "country": "United Kingdom of Great Britain and Northern Ireland [GB]",
                "region": "England",
                "city": "London",
                "coordinates": "51.508530, -0.125740 (51°30'31\"N 0°7'33\"W)"
            },
            "as_information": {
                "asn": "AS51561",
                "as_name": "AS-ICUK",
                "organization": "ICUK Computing Services Limited",
                "total_ipv4_prefixes": 56,
                "total_ipv4_address": 58690
            },
            "vendor_information": {
                "cpes": [
                    "o:microsoft:windows",
                    "a:microsoft:internet_information_services",
                    "a:microsoft:internet_information_services:7.5"
                ]
            },
            "security_evaluation": {
                "open_ports": [
                    {"port_number": 80, "service_name": "HTTP"},
                    {"port_number": 264, "service_name": "CHECKPOINT_TOPOLOGY"},
                    {"port_number": 389, "service_name": "LDAP"},
                    {"port_number": 443, "service_name": "HTTP"},
                    {"port_number": 4433, "service_name": "HTTP"}
                ],
                "vulnerabilities": [
                    "CVE-2010-1899",
                    "CVE-2010-3972",
                    "CVE-2010-2730"
                ]
            }
        },
        '132.235.231.170': {
            "detected_modifications": [
                "Receiver Window or Urgent Pointer Modified"
            ],
            "geolocation_information": {
                "country": "United States of America [US]",
                "region": "Ohio",
                "city": "Athens",
                "coordinates": "39.316150, -82.095210 (39°18'58\"N 82°5'43\"W)"
            },
            "as_information": {
                "asn": "AS17135",
                "as_name": "OHIOU",
                "organization": "Ohio University",
                "total_ipv4_prefixes": 4,
                "total_ipv4_address": 82688
            },
            "vendor_information": "Vendor could not be identified",
            "security_evaluation": "No information available"
        },
        '132.235.185.140': {
            "detected_modifications": [
                "Timestamp Removed or Data set to 0",
                "Complete Hash Modified",
                "TCP Sack Permitted Removed",
                "TCP Timestamp Removed",
                "TCP NOP Added"
            ],
            "geolocation_information": {
                "country": "United States of America [US]",
                "region": "Ohio",
                "city": "Athens",
                "coordinates": "39.316150, -82.095210 (39°18'58\"N 82°5'43\"W)"
            },
            "as_information": {
                "asn": "AS17135",
                "as_name": "OHIOU",
                "organization": "Ohio University",
                "total_ipv4_prefixes": 4,
                "total_ipv4_address": 82688
            },
            "vendor_information": "Vendor could not be identified",
            "security_evaluation": "No information available"
        }
    }

    return ip_data.get(ip, {"error": "IP address not found"})
