import csv
import json

def get_path(asn):
    if asn == 15625:
        csvFilePath = "/home/catrin/data/dataset/path-finding/ing.csv"
        data = get_json_from_csv(csvFilePath)
    elif asn == 15916:
        csvFilePath = "/home/catrin/data/dataset/path-finding/abn.csv"
        data = get_json_from_csv(csvFilePath)
    elif asn == 40985:
        csvFilePath = "/home/catrin/data/dataset/path-finding/eneco.csv"
        data = get_json_from_csv(csvFilePath)
    else:
        data = { 'error': 'Invalid input'}
    return data

def get_json_from_csv(csvFilePath):
    # create a dictionary
    data = {}

    # Open a csv reader called DictReader
    with open(csvFilePath, encoding='utf-8') as csvf:
        csvReader = csv.DictReader(csvf)
        # Convert each row into a dictionary
        # and add it to data
        for rows in csvReader:
            # Assuming a column named 'No' to
            # be the primary key
            key = rows['No']
            data[key] = rows
    return data
