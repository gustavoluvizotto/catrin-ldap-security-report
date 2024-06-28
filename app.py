__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from flask import Flask, request, jsonify
import clickhouse_connect as chc

from dataset_handler import init_dataset, load_dataset, delete_dataset
import scanning_query as sq
import credentials_clickhouse as c


app = Flask("NIP")
dataset_scanning = None
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
    #global dataset_scanning
    #if dataset_scanning is None:
    #    return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": '"ip_prefix" must be provided for the query.'}), 400

    return sq.scanning_query(clickhouse_client, ip_prefix, dataset_scanning)


@app.route("/scanning_report", methods=["GET"])
def report():
    global dataset_scanning
    if dataset_scanning is None:
        return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": '"ip_prefix" must be provided for the query.'}), 400

    return jsonify({"error": "Not implemented yet."}), 500


def perform_dummy_query(dataset):
    for d in dataset.values():
        d.groupBy("port").count().show()


if __name__ == "__main__":
    #init_dataset()
    #dataset_scanning = load_dataset()
    #perform_dummy_query(dataset_scanning)

    clickhouse_client = chc.get_client(host='localhost', port=8123, username='default', password=c.default_user)

    app.run(port=5000, host="0.0.0.0", use_reloader=False, debug=True)

    #delete_dataset(dataset_scanning)
    dataset_scanning = None
