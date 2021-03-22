"""
file: compareFuncs.py
date: 11/03/2019
author: binpang

compare the function information 
between ground truth(ccr) and compared tool
"""
import optparse
import logging
import traceback
import string
import random
import os
import capstone as cs

from protobuf_def import blocks_pb2
from elftools.elf.elffile import ELFFile
from capstone import x86
from BlockUtil import *


logging.basicConfig(format = "%(asctime)-15s %(levelname)s:%(message)s", level=logging.DEBUG)

textAddr = 0
textSize = 0
textOffset = 0
MD = None

# FIXME: sometimes, ccr(clang) version can't linke our compiled gcc libraries to its executable, 
# so we exclude below functions which is added by linker. 
LINKER_ADDED_FUNCS = {
        'deregister_tm_clones',
        'register_tm_clones',
        '__do_global_dtors_aux',
        'frame_dummy',
        '__x86.get_pc_thunk.bx',
        '__x86.get_pc_thunk.dx',
        '__x86.get_pc_thunk.ax',
        '__x86.get_pc_thunk.cx',
        '_fini',
        '_init',
        '_start',
        # eh_frame has records of below funcs
        '__libc_csu_fini',
        '__libc_csu_init',
        }

linker_libc_func = {
               "__x86.get_pc_thunk.bx", # glibc in i386 function
               "__libc_csu_init",
               "__libc_csu_fini",
               "deregister_tm_clones",
               "register_tm_clones",
               "__do_global_dtors_aux",
               "frame_dummy",
               "_start",
               "atexit",
               "_dl_relocate_static_pie",
               "__stat",
               "stat64",
               "fstat64",
               "lstat64",
               "fstatat64",
               "__fstat"
               }
groundTruthFuncRange = dict()

BLACKLIST_ADDRS = set()

# we record the linker function address, and then check which function we have omited
def getLinkerFunctionAddr(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        symsec = elffile.get_section_by_name('.symtab')
        get_pc_thunk_bx = 0x0
        global linkerFuncAddr
        if symsec == None:
            return
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' != sym.entry['st_info']['type']:
                continue
            #try:
                #name = cxxfilt.demangle(sym.name)
            #except:
            #    continue
            #print(name)
            if sym.name in linker_libc_func:
                linkerFuncAddr.add(sym['st_value'])

'''
read function information from symbol information
'''
def readFuncsFromSyms(binary):

    result = set()
    global BLACKLIST_ADDRS

    with open(binary, 'rb') as open_file:
        elffile = ELFFile(open_file)
        symsec = elffile.get_section_by_name('.symtab')
        if not symsec:
            logging.error("binary file %s does not contains .symtab section!" % (binary))
            return result 
        for sym in symsec.iter_symbols():
            if 'STT_FUNC' == sym['st_info']['type'] and sym['st_value'] != 0x0 and \
                    isInTextSection(sym['st_value']):
                #logging.debug("[Find Func Start From .symtab]: address 0x%x" % (sym['st_value']))
                result.add(sym['st_value'])
                if sym.name in LINKER_ADDED_FUNCS:
                    BLACKLIST_ADDRS.add(sym['st_value'])

    return result

def randomString(stringLength=10):
    """Generate a random string of fixed length """

    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

linkerFuncAddr = set()
# pie/pic base address
# angr base address is 0x400000
# ghidra base address is 0x100000
# others are 0x0
BASE_ADDR_MAP = {"angr": 0x400000, "ghidra": 0x100000}
disassembler_base_addr = 0x0
PIE = False

def compareFuncs(groundTruth, compared, ehFuncs):
    """
    compare the jump tables
    """
    logging.info("Compare Funcs Start:")
    falsePositive = 0 # false positive number
    falseNegitive = 0 # false negitive number
    truePositive = 0
    found = 0
    tmpFunc = set()
    print(len(ehFuncs), "eh num")
    for func in compared:
        if func not in ehFuncs:
            tmpFunc.add(func)
    ## compute the false positive number
    sym_blacklist_num = 0
    linker_num = 0
    for func in tmpFunc:
        if func not in groundTruth:
            logging.error("[Func Start False Positive #{0}]:Function Start 0x{1:x} not in Ground Truth.".format(falsePositive, func))
            falsePositive += 1
        elif func in BLACKLIST_ADDRS:
            sym_blacklist_num += 1
        elif func in linkerFuncAddr:
            linker_num += 1
        else:
            found += 1
            logging.error("[Func Start Identified #{0}]:Function Start 0x{1:x} in Ground Truth.".format(falsePositive, func))
     #   elif func not in ehFuncs:
      #      truePositive += 1


    ## compute the false negitive number
    for func in tmpFunc:
        if func not in compared:
            if func in BLACKLIST_ADDRS:
                continue
            logging.error("[Func Start False Negitive #{0}]:Function Start 0x{1:x} not in compared.".format(falseNegitive, func))
            falseNegitive += 1
    print("[Result]:The total Functions in ground truth is %d" % (len(groundTruth) - sym_blacklist_num))
    print("[Result]:The total Functions in compared is %d" % (len(tmpFunc)))
    print("[Result]:Linker Function number is %d" % (linker_num))
    print("[Result]:Extra False positive number is %d" % (falsePositive))
    print("[Result]:Identified Function number is %d" % (found))
    print("[Result]:False negative number is %d" % (falseNegitive))
    #print("[Result]:Recall rate is %f" % (truePositive / (len(groundTruth) - sym_blacklist_num)))
    #print("[Result]:Precision rate is %f" % (truePositive / len(compared)))


def readFuncs(mModule, groundTruth):
    """
    read Funcs from protobufs
    params:
        mModule: protobuf module
    returns:
        Funcs start: store the result of function start
    """
    global groundTruthFuncRange
    tmpFuncSet = set()
    for func in mModule.fuc:
        # this is the dummy function
        if func.va == 0x0:
            continue
        funcAddr = func.va
        if PIE and not groundTruth:
            funcAddr = funcAddr - disassembler_base_addr
        if not isInTextSection(funcAddr):
            continue
        if funcAddr not in tmpFuncSet:
            tmpFuncSet.add(funcAddr)
        else:
            logging.warning("repeated handle the function in address %x" % func.va)
            continue

    if groundTruth:
        for func in linkerFuncAddr:
            if func not in tmpFuncSet:
                logging.debug("add linker add function that 0x%x" % func)
                tmpFuncSet.add(func)

        for func in mModule.fuc:
            for bb in func.bb:
            # collect the range of padding bytes
                for inst in bb.instructions:
                    groundTruthFuncRange[inst.va] = inst.size

    return tmpFuncSet

def readTextSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        for sec in elffile.iter_sections():
            if sec.name == '.text':
                global textSize 
                global textAddr
                global textOffset
                pltSec = sec
                textSize = pltSec['sh_size']
                textAddr = pltSec['sh_addr']
                textOffset = pltSec['sh_offset']
                logging.info(".text section addr: 0x%x, size: 0x%x, offset: 0x%x" % (textAddr, textSize, textOffset))

def isInTextSection(addr):
    if addr >= textAddr and addr < textAddr + textSize:
        return True
    return False

"""
get pie base offset according to the compared file name.
"""
def getPIEBaseOffset(comparedFile):
    for (tool, base_offset) in BASE_ADDR_MAP.items():
        if tool in comparedFile:
            return base_offset
    # default offset is 0
    return 0

def doubleCheckGhidraBase(compared):
    '''
    sometimes, ghidra do not set pie/pic object base address as 0x100000, we double check it!
    '''
    invalid_count = 0x0
    global disassembler_base_addr
    for func in compared.fuc:
        # emmm, func.va - disassembler_base_addr is not the valid address in .text section
        if not isInTextSection(func.va - disassembler_base_addr):
            invalid_count += 1
    # need python3
    if invalid_count / len(compared.fuc) > 0.8:
        logging.warning("Change ghidra base address to 0x10000!")
        disassembler_base_addr = 0x10000

'''
read function information from .eh_frame section
'''
def readFuncsFromEhFrame(binary):
    logging.debug("strip binary is %s" % binary)
    try:
        result = dict()
        tmp_path = randomString()
        shell_command = "readelf --debug-dump=frames %s | grep 'pc=' | cut -f3 -d = | awk '{print $1}' > /tmp/%s" %\
            (binary, tmp_path)
        logging.debug(shell_command)
        os.system(shell_command)
        tmp_file = open('/tmp/%s' % tmp_path, 'r+')
        for line in tmp_file:
            splited_line = line.strip().split('.')
            func_start = int(splited_line[0], 16)
            func_end = int(splited_line[2], 16)
            logging.info("[Find Func Start From EH_FRAME]: address 0x%x, size is 0x%x" % (func_start, func_end - func_start))
            result[func_start] = func_end - func_start
        os.system('rm /tmp/%s' % (tmp_path))
    except Exception as e:
        traceback.print_exc()
        return None
    return result

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-g", "--groundtruth", dest = "groundtruth", action = "store", \
            type = "string", help = "ground truth file path", default = None)
    parser.add_option("-i", "--input", dest = "input", action = "store", \
            type = "string", help = "compared file path", default = None)
    parser.add_option("-b", "--binaryFile", dest = "binaryFile", action = "store", \
            type = "string", help = "binary file path", default = None)
    parser.add_option("-e", "--ehframe", dest = "ehframe", action = "store", \
            type = "string", help = "ehframe file path", default = None)

    (options, args) = parser.parse_args()

    assert options.groundtruth != None, "Please input the ground truth file!"
    assert options.input!= None, "Please input the compared file!"
    assert options.binaryFile != None, "Please input the binary file!"
    assert options.ehframe != None, "Please input the ehframe file!"

    readTextSection(options.binaryFile)
    logging.debug("compared file is %s" % options.binaryFile)
    getLinkerFunctionAddr(options.binaryFile)
    mModule1 = blocks_pb2.module()
    mModule2 = blocks_pb2.module()
    mModule3 = blocks_pb2.module()
    try:
        f1 = open(options.groundtruth, 'rb')
        mModule1.ParseFromString(f1.read())
        f1.close()
    except IOError:
        print(options.groundtruth)
        print("Could not open Ground Truth file\n")
        exit(-1)

    try:
        f2 = open(options.input, 'rb')
        mModule2.ParseFromString(f2.read())
        f2.close()
    except IOError:
        print(options.input)
        print("Could not open the input file\n")
        exit(-1)
    try:
        f3 = open(options.ehframe, 'rb')
        mModule3.ParseFromString(f3.read())
        f3.close()
    except IOError:
        print("Hello", options.ehframe)
        print("Could not open the ehframe file\n")
        exit(-1)
    if "find.strip" in options.ehframe:
        print("Skip /findutils/find file")
        exit(-1)
    truthFuncs = readFuncs(mModule1, True)
    pbFuncs = readFuncs(mModule2, False)
    ehFuncs = readFuncs(mModule3, False)
    not_included = checkGroundTruthFuncNotIncluded(groundTruthFuncRange, options.binaryFile)
    if not_included != None:
        logging.debug("Append the not included functions! {0}".format(not_included))
        truthFuncs |= not_included

    #comparedFuncs = readFuncsFromEhFrame(options.strip)

    compareFuncs(truthFuncs, pbFuncs, ehFuncs)
