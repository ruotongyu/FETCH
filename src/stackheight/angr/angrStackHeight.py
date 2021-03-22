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
import stackheight_pb2


#logging.basicConfig(level=logging.DEBUG)
#logging.getLogger('angr.analyses.stack_pointer_tracker').setLevel(logging.INFO)
def dumpBlocks(binary, output):
    # "force_complete_scan" default is True
    p = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFGFast(normalize = True)
    
    sp = p.arch.sp_offset
    regs = {sp}
    stack = stackheight_pb2.StackHeights()
    for func_addr in cfg.functions:
        func = cfg.functions[func_addr]
        if func.alignment:
            continue
        try:
            sptracker = p.analyses.StackPointerTracker(func, regs, track_memory=False)
        except:
            continue
        for bb in func.blocks:
            #print("basic block addr 0x%x, its size 0x%x" % (bb.addr, bb.size))
            #for key in sptracker.states().keys():
            cfg_node = cfg.get_any_node(bb.addr)
            if bb.size != 0 and cfg_node != None:
                for inst in bb.capstone.insns:
                    pbStack = stack.heights.add()
                    inst_va = inst.address
                    sp_result = sptracker.offset_before(inst_va, sp)
                    if sp_result == None:
                        #print("None Object:", hex(bb.addr))
                        continue
                    else:
                        pbStack.address = inst_va
                        if sp_result >= 9223372036854775808:
                            sp_result = 18446744073709551616 - sp_result
                        pbStack.height = sp_result
                        #print("Block Address: ", hex(inst_va), "SP Stack Pointer Offset: ", hex(sp_result))
    f = open(output, "wb")
    f.write(stack.SerializeToString())
    f.close()
    #for func_addr in cfg.functions:
     #   func = cfg.functions[func_addr]

      #  if func.alignment:
       #     print("function 0x%x is alignment function, skip!" % (func.addr))
        #    continue
        #print("function %s, its addr is 0x%x" % (func.name, func.addr))
        # iter over blocks
        #for bb in func.blocks:
            #print("basic block addr 0x%x, its size 0x%x" % (bb.addr, bb.size))
            #cfg_node = cfg.get_any_node(bb.addr)
            # bb.instruction_addrs can get the instrction address of block
            
            #if cfg_node != None and bb.size != 0:
            #    successors = cfg_node.successors
            #    for suc in successors:
            #        print("Edge 0x%x -> 0x%x" % (bb.addr, suc.addr))

                # iter over instructions
                # bb.instruction_addrs may have bug
                # we use capstone instead to extract instuction
                # for inst in bb.instruction_addrs:
            #    for inst in bb.capstone.insns:
            #        inst_va = inst.address
            #        instruction = pbBB.instructions.add()
            #        instruction.va = inst_va
            #        print("instruction: 0x%x" % (instruction.va))
                    # can't get its size from angr for now

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", dest = "output", action= "store", type = "string", \
            help = "output of the protobuf file", default = "/tmp/angr_blocks.pb2") 
    parser.add_option("-b", "--binary", dest = "binary", action = "store", type = "string", \
            help = "binary file", default = None)
    #parser.add_option("-s", "--statistics", dest = "statistics", action= "store", type = "string", \
    #        help = "output of statistics of the tool. Such as the count of function matching.", default= "/tmp/angr_statics.log")
    (options, args) = parser.parse_args()
    if options.binary == None:
        print("please input the binary file")
        exit(-1)

    dumpBlocks(options.binary, options.output)
