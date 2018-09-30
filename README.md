# NgramCNN
A Ngram based convolution neural network for graph objects classification.
The major idea of this approach is normalizing the graph objects and applying the specific convolutional neural layers to extract the subgraph structures from graph objects.
Those subgraph structures can be quite complicated while provide great contribution in classification task.

Here is the websize http://www.bruceluo.net/ngramcnn.html.

## FILES
NgramCNN source code package contains four files and four folders.

* ngramcnn.py
* ngramcnn_utils.py
* kdd_datasets/
* bufferdata/
* logdata/

## DEPENDENCY
Python 2.7 is required for NgramCNN.

Besides, following libs are needed:

* tensorflow
* numpy
* itertools-recipes
* futures
* six

Both these libs can be downloaded from their website (just google them) or installed by pip.
```bash
$pip install numpy futures itertools_recipes six tensorflow 
```

## DEMO

NgramCNN's demo contains two parts.

Preprocessing
-
The tamplate is as follows:
```bash
python ngramcnn.py <datasetname> 1 <kernel_width>
```
In this script, the first arg is the dataset name, see folder "kdd_datasets".

The second arg denotes current operation is preprcessing.

The third arg denotes the kernel size, namely the n in ngram.

This script will handle the data from dataset and write into the buffer dir.

A toy example is as follows:
```bash
python ngramcnn.py ptc 1 7
```

Training
-
```bash
python ngramcnn.py <datasetname> 2 <kernel_width> <batch_size> <diag_kernel_num> <conv_kernel_size> <conv_kernel_num> <epoch_num> <dropout_ratio>
```

In training, the batch_size means the minibatch size used in training.

diag_kernel_num means the number of kernels in diagonal convoltion.

conv_kernel_size and conv_kernel_num denote the kernel size and number in rest convoltion layers, resp.

epoch_num denotes the max epoch iteration number.

dropout_ratio is the parameter in dropout.

An example is:
```bash
python ngramcnn.py ptc 2 7 100 20 7 20 200 0.5
```

Note that we developed and tested these codes in MacOS and Ubuntu.

Windows OS may not support some OS commands and you can just remove those codes.

In default, the GPU is required.

Nvidia GeForce 1080 and titanX are suggested configuration.


## Data Schema
```json
{
  "graph": [
    # graph 0
    {
      "0": {
        "neighbors": [1, 2],
        "label": (1,)
      },
      "1": {
        "neighbors": [0, 2],
        "label": (2,)
      },
      ...
    },
    # graph 1
    {

    },
    ...
  ],
  "labels": [1, 0, 1, 0, ...] 
}
```

You can get all graphs by key "graph" and get all corresponding labels by key "labels".
The return values are both list with equal length.
For each graph, it is a dict. The keys of this dict are ids of node (could be any string).
The values of the dict are another dict, which has two keys.
One is "neighbors", whose value is a list of node ides. The other is 'label', whose value is a tuple.

## REFERENCE

Please cite our publication if you'd like to use our code (for comparison and promotion).

        @article{luo2017deep,
          title={Deep Learning of Graphs with Ngram Convolutional Neural Networks},
          author={Luo, Zhiling and Liu, Ling and Yin, Jianwei and Li, Ying and Wu, Zhaohui},
          journal={IEEE Transactions on Knowledge and Data Engineering},
          volume={29},
          number={10},
          pages={2125--2139},
          year={2017},
          publisher={IEEE}
        }


## CONTACT

Contact me if you have any questions about the code and its execution.

Dr. Bruce Luo

luozhiling@zju.edu.cn

The latest code version will be released in my homepage.

http://www.bruceluo.net

That's all, forks.
