import os
import json


if __name__ == "__main__":
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
    with open('G:/Coding/NgramCNN/kdd_datasets/CWE-119.json', 'w') as fp:
        json.dump(all_graphs, fp)


