# Finds the path between a source ASN and a destination prefix
# As an example, we take source ASN as 15916 and destination as 52.96.0.0/12 (AS8075(Microsoft))
import pybgpstream
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import csv
import pickle
import sys
from time import gmtime, strftime


# Convert ASes on AS_Path attribute to list
def as_path_to_list(as_path):
    
    as_list = []

    for asn in as_path:
        as_list.append(int(asn))

    return(as_list)

def add_edge_to_graph(graph, as_path):
    path_len = len(as_path)
    for k,asn in enumerate(as_path):
        if (k+1) is not path_len:
            graph.add_edge(as_path[k],as_path[k+1])

# Find paths from MS ASN(8075) to route collectors
def as_path_dst_rc(graph, dst_pfx):
    start_time = strftime("%Y-%m-%d 00:00:00", gmtime())
    end_time = start_time
    stream = pybgpstream.BGPStream(
        from_time=start_time,
        until_time = end_time,
        collectors=["rrc00"],
        record_type="ribs",     
        filter = 'prefix less '+dst_pfx # Look for prefix less specific than given prefix
       )
    
    # Find paths from MS ASN to route collectors
    for rec in stream.records():
        for elem in rec:
            as_path1 = as_path_to_list(elem.fields["as-path"].split())
            add_edge_to_graph(graph, as_path1) 
    return graph

# Find paths from AS15916 to route collectors
def as_path_source_rc(src_asn, graph):
    start_time = strftime("%Y-%m-%d 00:00:00", gmtime())
    end_time = start_time
    stream = pybgpstream.BGPStream(
        from_time=start_time,
        until_time=end_time,
        collectors=["rrc00"],
        record_type="ribs",     
            filter = 'path _'+src_asn #Look for all the prefixes originated by AS15916
       )
    
    # Find paths from MS ASN to route collectors
    for rec in stream.records():
        for elem in rec:
            as_path2 = as_path_to_list(elem.fields["as-path"].split())
            add_edge_to_graph(graph, as_path2) # Merge edges and vertices to the same graph object
    return graph



def main(source, dst_pfx):
    # Change source and destination as per requirments here
    # source = "15916"
    # dst_pfx = "52.96.0.0/12"
    graph = nx.Graph()

    # Path from destination prefix to route collector
    graph1 = as_path_dst_rc(graph, dst_pfx)

    # Dump graph object into pickle form
    with open(
            'graph1.p',
            'wb') as pickleFile:
        pickle.dump(graph1, pickleFile)

    # Merge a graph obtained from destinaton prefix to route collector, with path from a source AS to Route collector
    graph2 = as_path_source_rc(source, graph1)

    # Dump graph object into pickle form
    with open(
            'pickle_file_source_dst_prefix.p',
            'wb') as pickleFile:
        pickle.dump(graph2, pickleFile)

    # Unpickle a pickle file to get a Graph object
    with open(
            'pickle_file_source_dst_prefix.p',
            'rb') as pickleFile:
        graph_new = pickle.load(pickleFile)
    print(graph_new)

    dest = "8075"
    # Get all the paths with cutoff = 5 (No. of nodes between a source and a destination)
    paths = nx.all_simple_paths(graph_new, int(source), int(dest), cutoff=5)

    # Save all the paths into a file
    df = pd.DataFrame(paths)
    df.to_csv('path_src_dst.csv',index=False, header=False)

    # TODO: For the next hackathon, Check valley free conditions


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python path_finding_dst_pfx.py <source> <dst_pfx>")
    else:
        main(sys.argv[1], sys.argv[2])
