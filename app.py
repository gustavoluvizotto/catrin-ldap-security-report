__author__ = "Gustavo Luvizotto Cesar"

import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import clickhouse_connect as chc

import scanning_query as sq
import scanning_report as sr
import security_events as se
import credentials_clickhouse as c


app = Flask("NIP")
CORS(app, resources={r"/*": {"origins": "http://demodev.responsible-internet.org"}})
clickhouse_client = None


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


@app.route("/scanning_events", methods=["POST"])
def security_events_push():
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    logs = [json.loads(log) for log in request.data.decode("utf-8").splitlines()]

    return se.push(clickhouse_client, logs)


@app.route("/scanning_events", methods=["GET"])
def security_events_query():
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": '"ip_prefix" must be provided for the query.'}), 400

    return se.query(clickhouse_client, ip_prefix)


@app.route("/scanning_events", methods=["DELETE"])
def security_events_prune():
    global clickhouse_client
    if clickhouse_client is None:
        return jsonify({"error": "No dataset loaded."}), 500

    uids = [json.loads(log) for log in request.data.decode("utf-8").splitlines()]

    return se.prune(clickhouse_client, uids)

# TODO: Implement a publish subscriber model for security events


if __name__ == "__main__":
    clickhouse_client = chc.get_client(host=c.host, port=c.port, username=c.default_user, password=c.default_password)

    app.run(port=5000, host="0.0.0.0", use_reloader=False, debug=True)
