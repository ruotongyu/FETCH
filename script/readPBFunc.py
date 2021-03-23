import blocks_pb2
import optparse
import argparse


def parse_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, default='None', required=False, help="path of the input file")
    options = parser.parse_args()
    return options


def func_addr(mModule):
    func_set = set()
    for func in mModule.fuc:
        func_set.add(func.va)
        print("Function Addr:", hex(func.va))
    return func_set


if __name__ == "__main__":
    options = parse_argument()
    path = options.input
    f = open(path, "rb")
    mModule = blocks_pb2.module()
    mModule.ParseFromString(f.read())
    fuc_set = func_addr(mModule)
    #print(len(fuc_set))

