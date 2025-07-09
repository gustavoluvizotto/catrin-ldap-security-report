__author__ = "Gustavo Luvizotto Cesar"

import json
import traceback

import clickhouse_connect as chc
import credentials_clickhouse as c
import credentials_security_events as cse
import middlebox_data as mbdata
import path_data as pdata
import scanning_query as sq
import scanning_report as sr
import security_events as se
import show_mb_results as smr
import werkzeug
import werkzeug.exceptions
from flask import Flask, Response, jsonify, request
from flask_cors import CORS

app = Flask("NIP")
CORS(app, resources={r"/*": {"origins": "http://demodev.responsible-internet.org"}})
clickhouse_client = None

@app.errorhandler(500)
def handle_bad_request(e):
    app.logger.error(traceback.format_exception(e))
    return 'INTERNAL SERVER ERROR', 500


@app.route("/help", methods=["GET"])
def help():
    return jsonify({
        "help": {
            "description": "This help.",
            "parameters": {},
            "example": "curl -G http://nip.responsible-internet.org:5000/help",
        },
        "scanning_query": {
            "description": "Query the scanning dataset.",
            "parameters": {
                "ip_prefix": "The IP prefix to query. Must be in CIDR notation. The minimum prefix length is 20."
            },
            "example": 'curl -G -d "ip_prefix=192.168.0.0/24" http://nip.responsible-internet.org:5000/scanning_query',
        },
        "scanning_report": {
            "description": "Get a overview report from the scanning dataset.",
            "parameters": {
                "ip_prefix": "The IP prefix to query. Must be in CIDR notation. The minimum prefix length is 20."
            },
            "example": 'curl -G -d "ip_prefix=192.168.0.0/24" http://nip.responsible-internet.org:5000/scanning_report',
        }
    }), 200

@app.route("/scanning_query", methods=["GET"])
def scanning_query():
    '''
    :return: see sq.scanning_query
    '''
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": '"ip_prefix" must be provided for the query.'}), 400

    return sq.scanning_query(clickhouse_client, ip_prefix)


@app.route("/scanning_report", methods=["GET"])
def report():
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": '"ip_prefix" must be provided for the query.'}), 400

    return sr.scanning_report(clickhouse_client, ip_prefix)

@app.route('/middlebox_info/asn/<asn>', methods=['GET'])
def get_middlebox_data(asn):
    if asn not in address_map:
        abort(404, description="ASN not found")

    results = []
    for ip in address_map[asn]:
        if "could not detect" in ip.lower():
            continue
        data = show_mb_results(ip)
        if "error" not in data:
            score_result = calculate_middlebox_score(ip, data)
            score_result["asn"] = asn
            results.append(score_result)

    return jsonify({
        "asn": asn,
        "middleboxes": results
    })

@app.route('/middlebox_info/ip/<ip>', methods=['GET'])
def get_middlebox_by_ip(ip):
    # Search all IPs across all ASNs
    for asn, ip_list in address_map.items():
        if ip in ip_list:
            data = show_mb_results(ip)
            if "error" not in data:
                score_result = calculate_middlebox_score(ip, data)
                score_result["asn"] = asn
                score_result["raw_data"] = data  # Optionally include full raw middlebox data
                return jsonify(score_result)
            else:
                abort(404, description="IP data not found")
    abort(404, description="IP not found in known ASNs")

@app.route('/paths/<int:src_asn>/<int:dst_asn>', methods=['GET'])
def nip_list_paths(src_asn: int, dst_asn: int):
    path = pdata.get_path(src_asn, dst_asn)
    if path is None:
        return jsonify({ 'error': 'Path from that source asn does not exist'}), 404
    return jsonify(path)

@app.route("/security_events", methods=["POST"])
def security_events_push():
    if "X-API-Key" not in request.headers:
        return jsonify({"error": "API key is required."}), 403

    api_key = request.headers["X-API-Key"]
    if api_key not in cse.API_KEYS:
        return jsonify({"error": "Invalid API key."}), 403
    
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    try:
        try:
            logs = [json.loads(log) for log in request.data.decode().splitlines()]
        except:
            logs = [json.loads(request.data.decode())]
    except:
        return jsonify({"error": "Invalid JSON format."}), 400

    return se.push(clickhouse_client, logs)


@app.route("/security_events", methods=["GET"])
def security_events_query():
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": '"ip_prefix" must be provided for the query.'}), 400

    return se.query(clickhouse_client, ip_prefix)


@app.route("/security_events", methods=["DELETE"])
def security_events_prune():
    if "X-API-Key" not in request.headers:
        return jsonify({"error": "API key is required."}), 403

    api_key = request.headers["X-API-Key"]
    if api_key not in cse.API_KEYS:
        return jsonify({"error": "Invalid API key."}), 403
    
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    uids = [json.loads(log) for log in request.data.decode("utf-8").splitlines()]

    return se.prune(clickhouse_client, uids)

# TODO: Implement a publish subscriber model for security events


if __name__ == "__main__":
    clickhouse_client = chc.get_client(host=c.host, port=c.port, username=c.default_user, password=c.default_password)

    app.run(port=5000, host="0.0.0.0", use_reloader=False, debug=True)
