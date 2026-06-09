import argparse
import json
import os
import sys

import pandas as pd


def main():
    parser = argparse.ArgumentParser(
        description="Read an MTR result file and print its content in JSON Lines format."
    )
    parser.add_argument("target", help="IP address or domain name to look up")
    args = parser.parse_args()

    target = args.target
    results_dir = os.environ.get("MTR_RESULTS_DIR", "/app/results")
    filename = os.path.join(results_dir, f"mtr_{target}.csv")

    if not os.path.exists(filename):
        print(json.dumps({"error": f"File not found: {filename}"}))
        sys.exit(1)

    df = pd.read_csv(filename)

    # Strip whitespace from column names, then drop the blank separator column
    # and the empty "Unnamed" column produced by the header's trailing comma.
    df.columns = df.columns.str.strip()
    df = df.loc[:, (df.columns != "") & ~df.columns.str.startswith("Unnamed")]

    print(df.to_json(orient="records", lines=True))


if __name__ == "__main__":
    main()
