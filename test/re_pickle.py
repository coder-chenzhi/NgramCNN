import pickle


def py2text_to_py3binary():
    with open("../kdd_datasets/ptc.graph", "r") as f:
        data = pickle.load(f)
        with open("../kdd_datasets/ptc.graph.py3", "wb") as fb:
            pickle.dump(data, fb)


if __name__ == "__main__":
    py2text_to_py3binary()

