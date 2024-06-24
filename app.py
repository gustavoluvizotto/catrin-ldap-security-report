from flask import Flask, request, jsonify
import pandas as pd

app = Flask("security-report")
dataset = None

@app.route('/load', methods=['POST'])
def load_dataset():
    global dataset
    data = request.json
    file_path = data.get('file_path')
    if not file_path:
        return jsonify({"error": "File path not provided"}), 400

    try:
        dataset = pd.read_csv(file_path)
        return jsonify({"message": f"Dataset loaded from {file_path}."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/query', methods=['GET'])
def query_dataset():
    global dataset
    if dataset is None:
        return jsonify({"error": "No dataset loaded. Please load a dataset first."}), 400

    column = request.args.get('column')
    value = request.args.get('value')
    if not column or not value:
        return jsonify({"error": "Both column and value must be provided for the query."}), 400

    try:
        result = dataset[dataset[column] == value].to_dict(orient='records')
        return jsonify(result)
    except KeyError:
        return jsonify({"error": f"Column '{column}' does not exist in the dataset."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(port=5000, debug=True)
