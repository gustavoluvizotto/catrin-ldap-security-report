import middlebox_data as mbdata

def get_info_for_address(address):
    middlebox_ips = mbdata.get_middlebox_ips(address)
    results = [get_info_for_ip(ip) for ip in middlebox_ips]
    return {
        "target_ip": address,
        "middlebox_ips": results
    }

def get_info_for_ip(ip):
    return {
        "ip": ip,
        "details": mbdata.show_mb_results(ip)
    }