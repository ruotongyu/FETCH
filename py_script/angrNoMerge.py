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
protobuf_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../protobuf_def")
# sys.path.append("../protobuf_def")
sys.path.append(protobuf_path)
# sys.path.append("./protobuf_def")
import blocks_pb2

    
#logging.basicConfig(level=logging.DEBUG)
logging.getLogger('angr.analyses').setLevel(logging.DEBUG)
def dumpBlocks(binary, output):
    # "force_complete_scan" default is True
    p = angr.Project(binary, load_options={'auto_load_libs': False, 'load_debug_info':True})
    cfg = p.analyses.CFGFast(normalize = True, function_prologues=False, force_complete_scan=False)
    # output func matching counts
    module = blocks_pb2.module()

    # iter over the cfg functions
    for func_addr in cfg.functions:
        func = cfg.functions[func_addr]

        if func.alignment:
            print("function 0x%x is alignment function, skip!" % (func.addr))
            continue
        pbFunc = module.fuc.add()
        pbFunc.va = func_addr
        print("function %s, its addr is 0x%x" % (func.name, func.addr))
        # iter over blocks
        for bb in func.blocks:
            print("basic block addr 0x%x, its size 0x%x" % (bb.addr, bb.size))
            cfg_node = cfg.get_any_node(bb.addr)
            # bb.instruction_addrs can get the instrction address of block
            if cfg_node != None and bb.size != 0:
                pbBB = pbFunc.bb.add()
                pbBB.va = bb.addr
                pbBB.size = bb.size
                pbBB.parent = func_addr
                successors = cfg_node.successors
                for suc in successors:
                    child = pbBB.child.add()
                    child.va = suc.addr
                    print("Edge 0x%x -> 0x%x" % (bb.addr, suc.addr))

                # iter over instructions
                # bb.instruction_addrs may have bug
                # we use capstone instead to extract instuction
                # for inst in bb.instruction_addrs:
                for inst in bb.capstone.insns:
                    inst_va = inst.address
                    instruction = pbBB.instructions.add()
                    instruction.va = inst_va
                    print("instruction: 0x%x" % (instruction.va))
                    # can't get its size from angr for now
    f = open(output, "wb")
    f.write(module.SerializeToString())
    f.close()

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/angr_blocks.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    (options, args) = parser.parse_args()
    if options.binary == None:
        print("please input the binary file")
        exit(-1)

    dumpBlocks(options.binary, options.output)
