import argparse
import os


def parse_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, default='None', required=False, help="path of input file")
    options = parser.parse_args()
    return options

def readLog():
    logFile = open('/data/compare_ehframe/ana_fp.log', 'r')
    addr_dict = {}
    fileName = ''
    addr_set = set()
    prev_item = ''
    for line in logFile:
        
        if (str(line)[0:2] == './'):
            if fileName != '':
                addr_dict[fileName] = addr_set
                addr_set = set()
            fileName = str(line)

        if (str(line)[0:2] == '=='):
            addr = str(line).split(' ')[1]
            addr = addr.strip()
            addr_set.add(addr)
            prev_item = addr
        if (str(line)[0:2] == 'FP'):
            if "cold" not in str(line):
                addr_set.remove(prev_item)
    return addr_dict

def read():
    open()


if __name__ == "__main__":
    options = parse_argument()
    path = options.input
    


