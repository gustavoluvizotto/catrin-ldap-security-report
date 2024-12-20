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
                "organization": "University of Maryland"
            }
        },
        '80.95.199.213': {
            "detected_modifications": [],
            "geolocation_information": {
                "country": "United Kingdom [GB]",
                "region": "England",
                "city": "London",
                "coordinates": "51.5074, -0.1278"
            },
            "as_information": {
                "asn": "AS12345",
                "organization": "Example Org"
            }
        },
        '132.235.231.170': {
            "detected_modifications": [
                "TCP Window Size Modified"
            ],
            "geolocation_information": {
                "country": "United States of America [US]",
                "region": "California",
                "city": "Los Angeles",
                "coordinates": "34.0522, -118.2437"
            },
            "as_information": {
                "asn": "AS67890",
                "organization": "Another Org"
            }
        },
        '132.235.185.140': {
            "detected_modifications": [],
            "geolocation_information": {
                "country": "United States of America [US]",
                "region": "Texas",
                "city": "Austin",
                "coordinates": "30.2672, -97.7431"
            },
            "as_information": {
                "asn": "AS54321",
                "organization": "Third Org"
            }
        }
    }
    return ip_data.get(ip, {})