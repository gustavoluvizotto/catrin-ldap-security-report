address_map = {
        'AS3257': ['199.73.21.102', '193.17.185.13', '92.60.242.196'],
        'AS702': ['212.208.54.219'],
        'AS8455': ['31.22.86.254'],
        'AS174': ['38.46.152.2', '38.119.166.3', '38.104.95.242', '204.29.160.6'],
        'AS8075': ['Couldn\'t detect any middlebox for this AS.']
    }

def get_middlebox_ips(asn):
    return address_map.get(asn, ['Could not detect a middlebox on the path to the target.'])

def show_mb_results(ip):
    middlebox_data = {

        '199.73.21.102': {
            "AS Information": {
                "ASN": "AS3257",
                "AS Name": "GTT Communications Inc.",
                "AS Country": "United States of America",
                "Usage Type": "Data Center/Web Hosting/Transit"
            },
            "Geolocation Information": {
                "Continent": "North America",
                "Country": "United States of America",
                "Region": "Massachusetts",
                "City": "Middleboro"
            },
            "Vendor Information": {
                "Vendor": "Palo Alto Networks",
                "Product": "PAN-OS"
            },
            "Open Ports": [
                {
                "Port Number": 22,
                "Service Name": "SSH"
                },
                {
                "Port Number": 80,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                },
                {
                "Port Number": 4443,
                "Service Name": "HTTPS"
                }
            ],
            "Vulnerabilities": [
                "CVE-2024-3400"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Timestamp TSVal Modified"
            ]
        },
        '193.17.185.13': {
            "AS Information": {
                "ASN": "AS3257",
                "AS Name": "GTT Communications Inc.",
                "AS Country": "United States of America",
                "Usage Type": "Data Center/Web Hosting/Transit"
            },
            "Geolocation Information": {
                "Continent": "Europe",
                "Country": "Germany",
                "City": "Munich"
            },
            "Vendor Information": {
                "Vendor": "pfSense",
                "Product": "FreeBSD"
            },
            "Open Ports": [
                {
                "Port Number": 80,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                },
                {
                "Port Number": 4443,
                "Service Name": "HTTPS"
                }
            ],
            "Vulnerabilities": [
                "CVE-2010-1899",
                "CVE-2010-3972"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Urgent Pointer/Receiver Window Modified"
            ]
        },
        '92.60.242.196': {
            "AS Information": {
                "ASN": "AS3257",
                "AS Name": "GTT Communications Inc.",
                "AS Country": "United States of America",
                "Usage Type": "Data Center/Web Hosting/Transit"
            },
            "Geolocation Information": {
                "Continent": "Europe",
                "Country": "Spain",
                "City": "Madrid"
            },
            "Vendor Information": {
                "Vendor": "Unkown",
                "Product": "Unkown"
            },
            "Open Ports": [
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                }
            ],
            "Vulnerabilities": [
                "No known vulnerabilities"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Timestamp Removal"
            ]
        },
        '193.17.185.13': {
            "AS Information": {
                "ASN": "AS3257",
                "AS Name": "GTT Communications Inc.",
                "AS Country": "United States of America",
                "Usage Type": "Data Center/Web Hosting/Transit"
            },
            "Geolocation Information": {
                "Continent": "Europe",
                "Country": "Germany",
                "City": "Munich"
            },
            "Vendor Information": {
                "Vendor": "pfSense",
                "Product": "FreeBSD"
            },
            "Open Ports": [
                {
                "Port Number": 80,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                },
                {
                "Port Number": 4443,
                "Service Name": "HTTPS"
                }
            ],
            "Vulnerabilities": [
                "CVE-2010-1899",
                "CVE-2010-3972"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Urgent Pointer/Receiver Window Modified"
            ]
        },
        '212.208.54.219': {
            "AS Information": {
                "ASN": "AS702",
                "AS Name": "Verizon Business EMEA",
                "AS Country": "United States of America",
                "Usage Type": "Commercial"
            },
            "Geolocation Information": {
                "Continent": "Europe",
                "Country": "France",
                "City": "Paris"
            },
            "Vendor Information": {
                "Vendor": "Fortinet",
                "Product": "Forti-OS"
            },
            "Open Ports": [
                {
                "Port Number": 23,
                "Service Name": "Telnet"
                },
                {
                "Port Number": 80,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                },
                                {
                "Port Number": 500,
                "Service Name": "IKE"
                }
            ],
            "Vulnerabilities": [
                "CVE-2023-51385",
                "CVE-2021-36368",
                "CVE-2023-51767",
                "CVE-2019-16905"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Timestamp Removal",
                "TCP Data Offset Modified",
                "TCP Sack Permitted Removal"
            ]
        },
        '31.22.86.254': {
            "AS Information": {
                "ASN": "AS8455",
                "AS Name": "atom86 BV",
                "AS Country": "Netherlands",
                "Usage Type": "Data Center/Web Hosting/Transit"
            },
            "Geolocation Information": {
                "Continent": "Europe",
                "Country": "Netherlands",
                "City": "Amstelveen"
            },
            "Vendor Information": {
                "Vendor": "Mikrotik",
                "Product": "RouterOS"
            },
            "Open Ports": [
                {
                "Port Number": 80,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                },
                {
                "Port Number": 500,
                "Service Name": "IKE"
                },
                                {
                "Port Number": 2000,
                "Service Name": "MIKROTIK-BW"
                }
            ],
            "Vulnerabilities": [
                "No known vulnerabilities"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added"
            ]
        },
        '38.46.152.2': {
            "AS Information": {
                "ASN": "AS174",
                "AS Name": "Cogent Communications",
                "AS Country": "United States of America",
                "Usage Type": "ISP"
            },
            "Geolocation Information": {
                "Continent": "North America",
                "Country": "Canada",
                "City": "Mississauga"
            },
            "Vendor Information": {
                "Vendor": "Check Point",
                "Product": "GAIA-OS"
            },
            "Open Ports": [
                {
                "Port Number": 264,
                "Service Name": "CHECKPOINT_TOPOLOGY"
                },
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                },
                {
                "Port Number": 500,
                "Service Name": "IKE"
                }
            ],
            "Vulnerabilities": [
                "No known vulnerabilities"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Timestamp TSVal Modified"
            ]
        },
        '38.119.166.3': {
            "AS Information": {
                "ASN": "AS174",
                "AS Name": "Cogent Communications",
                "AS Country": "United States of America",
                "Usage Type": "ISP"
            },
            "Geolocation Information": {
                "Continent": "North America",
                "Country": "United States of America",
                "Region": "Washington",
                "City": "Renton"
            },
            "Vendor Information": {
                "Vendor": "Redhat",
                "Product": "Enterprise Linux"
            },
            "Open Ports": [
                {
                "Port Number": 8122,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 8123,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 8143,
                "Service Name": "HTTP"
                },
                {
                "Port Number": 8180,
                "Service Name": "HTTP"
                }
            ],
            "Vulnerabilities": [
                "No known vulnerabilities"
            ],
            "Detected Modifications": [
                "IP Total Length Modified",
                "TCP Timestamp TSVal Modified",
                "TCP Data Offset Modified"
            ]
        },
        '38.104.95.242': {
            "AS Information": {
                "ASN": "AS174",
                "AS Name": "Cogent Communications",
                "AS Country": "United States of America",
                "Usage Type": "ISP"
            },
            "Geolocation Information": {
                "Continent": "North America",
                "Country": "United States of America",
                "Region": "Florida",
                "City": "Miami"
            },
            "Vendor Information": {
                "Vendor": "Check Point",
                "Product": "GAIA-OS"
            },
            "Open Ports": [
                {
                "Port Number": 264,
                "Service Name": "CHECKPOINT_TOPOLOGY"
                },
                {
                "Port Number": 500,
                "Service Name": "IKE"
                },
                {
                "Port Number": 18264,
                "Service Name": "HTTP"
                }
            ],
            "Vulnerabilities": [
                "CVE-2023-51385"
            ],
            "Detected Modifications": [
                "TCP MP Capable Removed",
                "TCP NOP Added",
                "TCP Timestamp TSVal Modified",
                "TSecr/RW or UP Modified"
            ]
        },
        '204.29.160.6': {
            "AS Information": {
                "ASN": "AS174",
                "AS Name": "Cogent Communications",
                "AS Country": "United States of America",
                "Usage Type": "ISP"
            },
            "Geolocation Information": {
                "Continent": "North America",
                "Country": "United States of America",
                "Region": "Florida",
                "City": "Jacksonville"
            },
            "Vendor Information": {
                "Vendor": "Palo Alto Networks",
                "Product": "PAN-OS"
            },
            "Open Ports": [
                {
                "Port Number": 443,
                "Service Name": "HTTPS"
                }
            ],
            "Vulnerabilities": [
                "No known vulnerabilities"
            ],
            "Detected Modifications": [
                "TCP Timestamp Tsecr Modified",
                "TCP Sack Permitted Removal",
                "TCP Sequence Number Modified"
            ]
        }

    }

    return middlebox_data.get(ip, {"error": "IP address not found"})
