__author__ = 'chenzhi'

import pickle

if __name__ == "__main__":
    data = {"a": "a",
            "b": [1, 2, 3]}
    with open("test_pickle", "w") as out:
        pickle.dump(data, out)

