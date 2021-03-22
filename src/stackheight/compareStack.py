"""
file: angrBlocks.py
date: 07/18/2019
author: binpang

Get basic block and function information

Basic block terminators inclue `call`
"""
import angr
import logging
import sys
import optparse
import os
from elftools.elf.elffile import ELFFile

protobuf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../protobuf_def")
# sys.path.append("../protobuf_def")
sys.path.append(protobuf_path)
# sys.path.append("./protobuf_def")
from proto import stackheight_pb2

textAddr = 0
textSize = 0

def readTextSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                global textSize 
                global textAddr
                pltSec = sec
                textAddr = pltSec['sh_addr']
                textSize = pltSec['sh_size']

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False
#logging.basicConfig(level=logging.DEBUG)
#logging.getLogger('angr.analyses.stack_pointer_tracker').setLevel(logging.INFO)

def printEh(ehStack):
    for key in ehStack.keys():
        print("Ehframe", hex(key), hex(ehStack[key]))

def compareHeight(ehframe, angr, tool):
    print(ehframe, angr)
    stack1 = stackheight_pb2.StackHeights()
    stack2 = stackheight_pb2.StackHeights()
    try:
        s1 = open(ehframe, 'rb')
        stack1.ParseFromString(s1.read())
        s1.close()
    except IOError:
        print("could not open file: ", ehframe)
        exit(-1)
    try:
        s2 = open(angr, 'rb')
        stack2.ParseFromString(s2.read())
        s2.close()
    except IOError:
        print("could not open file: ", angr)
        exit(-1)
    ehStack = readStackHeight(stack1)
    if len(ehStack) == 0:
        print("Fail to load Ehframe Result")
        exit(1)
    toolStack = readStackHeight(stack2)
    #printEh(ehStack)
    TP = 0
    FP = 0
    unknown = 0
    FN = 0
    Miss = 0
    for key in toolStack.keys():
        if not isInTextSection(key):
            continue
        if tool == "angr":
            stackHeight = toolStack[key] + 8
        else:
            stackHeight = abs(toolStack[key])
        if key in ehStack.keys():
            if stackHeight == ehStack[key]:
                TP+=1
                #print("True Positive", hex(key), "Tool:", stackHeight, "Ehframe: ", ehStack[key])
            else:
                if stackHeight == 4294967295 or stackHeight == 3735928559:
                    unknown+=1
                else:
                    FP+=1
                #print("False Positive", hex(key), "Tool:", stackHeight, "Ehframe:", ehStack[key])
        else:
            Miss+=1
            #print("Not in Ehframe:", hex(key), stackHeight)
    
    for key in ehStack.keys():
        if key not in toolStack.keys():
            FN+=1


    opt = ehframe.split("/")
    if opt[1] == 'utils':
        folder = opt[3]
    else:
        folder = opt[2]

    print("Optimization level is", folder)
    print("Number of Ehframe", len(ehStack), "Number of Angr", len(toolStack))
    print("Number of True Positive", TP)
    print("Number of False Positive", FP)
    print("Number of Unknown", unknown)
    print("Ehframe Missing Num", Miss)
    print("Number of Tool Missing", FN)


def readStackHeight(Stacks):
    res = {}
    for stack in Stacks.heights:
        res[stack.address] = stack.height
    return res

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-e", "--ehframe", dest = "ehframe", action= "store", type = "string", \
            help = "ehframe pb file", default = None) 
    parser.add_option("-a", "--angr", dest = "angr", action = "store", type = "string", \
            help = "angr pb file", default = None)
    parser.add_option("-t", "--tool", dest = "tool", action= "store", type = "string", \
            help = "disassemble tool.", default=None)
    (options, args) = parser.parse_args()
    if options.ehframe == None:
        print("please input the ehframe file")
        exit(-1)

    if options.angr == None:
        print("please input the angr file")
        exit(-1)
    binary = options.ehframe.replace("ehStackHeight_", "")
    binary = binary.replace(".pb", "")
    readTextSection(binary)
    compareHeight(options.ehframe, options.angr, options.tool)
