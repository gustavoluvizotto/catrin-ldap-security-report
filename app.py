__author__ = "Gustavo Luvizotto Cesar"
__email__ = "g.luvizottocesar@utwente.nl"

from flask import Flask, request, jsonify
from parallel_pandas import ParallelPandas

from dataset_handler import dataset_scanning, init_dataset, load_dataset, delete_dataset
from scanning_query import scanning_query as sq


ParallelPandas.initialize(n_cpu=4, split_factor=2, disable_pr_bar=True)
app = Flask("NIP")


@app.route("/scanning_query", methods=["GET"])
def scanning_query():
    global dataset_scanning
    if dataset_scanning is None:
        return jsonify({"error": "No dataset loaded."}), 500

    ip_prefix = request.args.get("ip_prefix")
    if not ip_prefix:
        return jsonify({"error": "\"ip_prefix\" must be provided for the query."}), 400

    return sq.scanning_query(ip_prefix, dataset_scanning)


@app.route("/scanning_report", methods=["GET"])
def report():
    return jsonify({"error": "Not implemented yet."})


if __name__ == "__main__":
    init_dataset()
    load_dataset()

    # client examples:
    # curl -G http://localhost:5000/report ; localhost == domain name or ip of the server
    # curl -G http://localhost:5000/query?ip_prefix=192.168.0.0/24 ; see the query_dataset function for max ip_prefix length
    # curl -G http://localhost:5000/query?asn=AS1234
    app.run(port=5000, host="0.0.0.0", debug=True)

    delete_dataset()
