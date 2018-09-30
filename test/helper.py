import os
import json


def write_to_json(node_limit):
    label_file = "G:/Coding/java/workspace/VulnerabilityDetection/data/CWE-119/CGD/cwe119_label.txt"
    filename_to_label = {}
    with open(label_file, "r") as f:
        lines = f.readlines()
        for line in lines:
            cols = line.split(" ")
            label = int(cols[-1])
            filename = cols[1].split("/")[-1]
            if filename in filename_to_label:
                filename_to_label[filename] = filename_to_label[filename] | label
            else:
                filename_to_label[filename] = label

    all_graphs = {"graph": [],
                  "labels": []}

    graphs_list = []
    labels_list = []
    code_path = "G:/Coding/java/workspace/VulnerabilityDetection/out/CWE-119"
    for filename in os.listdir(code_path):
        filepath = os.path.join(code_path, filename)
        if filename in filename_to_label:
            label = filename_to_label[filename]
        else:
            label = 0
        graph = {}
        with open(filepath, "r") as f:
            lines = f.readlines()
            # to control number of node
            if len(lines) > node_limit:
                continue
            for line in lines:
                node = line.strip().split(":")[0]
                neighors = line.strip().split(":")[1].split(",")
                if len(neighors) == 1 and neighors[0] == "":
                    neighors = []
                graph[node] = {"neighbors": neighors, "label": (0,)}
        graphs_list.append(graph)
        labels_list.append(label)
    all_graphs["graph"] = graphs_list
    all_graphs["labels"] = labels_list
    with open('G:/Coding/NgramCNN/kdd_datasets/CWE-119-{node_limit}-node.json'.format(node_limit=node_limit), 'w') as fp:
        json.dump(all_graphs, fp)


def summary_joern(source_path, output_path):
    output_file = open(os.path.join(output_path, "summary.dat"), "w")
    for root, dirs, files in os.walk(source_path, topdown=False):
        # 没有子目录，且文件名最后是C/C++的后缀
        if len(dirs) == 0 and root.endswith(tuple(["c", "cc", "cpp", "cxx", "h", "hpp"])):
            output_file.write(root + "\t")
            node_file = os.path.join(root, "nodes.csv")
            edge_file = os.path.join(root, "edges.csv")
            with open(node_file, "r") as f:
                output_file.write(str(len(f.readlines())) + "\t")
            with open(edge_file, "r") as f:
                output_file.write(str(len(f.readlines())) + "\n")
    output_file.close()


def parse_joern_to_json(source_path):
    for root, dirs, files in os.walk(source_path, topdown=False):
        # 没有子目录，且文件名最后是C/C++的后缀
        if len(dirs) == 0 and root.endswith(tuple(["c", "cc", "cpp", "cxx", "h", "hpp"])):
            print("parse", root)
            graph = {}
            edge_file = os.path.join(root, "edges.csv")
            with open(edge_file, "r") as f:
                edges = f.readlines()[1:]
                for edge in edges:
                    source = edge.strip().split()[0]
                    target = edge.strip().split()[1]
                    if source in graph:
                        cur_neighbors = graph[source]
                        if target not in cur_neighbors["neighbors"]:
                            cur_neighbors["neighbors"].append(target)
                    else:
                        graph[source] = {"neighbors": [target]}
            with open(os.path.join(root, "graph.json"), "w") as fp:
                json.dump(graph, fp)


if __name__ == "__main__":
    # with open('G:/Coding/NgramCNN/kdd_datasets/CWE-119-100-node.json', 'r') as fp:
    #     data = json.load(fp)
    # summary_joern("G:\Coding\VulDeePecker\joern_parsed\CWE-399\source_files",
    #               "G:\Coding\VulDeePecker\joern_parsed\CWE-399")
    parse_joern_to_json("G:\Coding\VulDeePecker\joern_parsed\CWE-399\source_files")


