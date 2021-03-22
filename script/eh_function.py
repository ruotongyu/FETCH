import refInf_pb2
import blocks_pb2
import optparse
import argparse
from BlockUtil import *
addr_dic = {}
pb_ref = {}
def parse_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, default='None', required=False, help="path of the input file")
    options = parser.parse_args()
    return options


def func_addr(mModule):
    func_set = set()
    for func in mModule.fuc:
        func_set.add(func.va)
    return func_set

def tar_addr(refInf):
    target_dic = {}
    for r in refInf.ref:
        ref = r.ref_va
        target = r.target_va
        target_dic[target] = ref
    return target_dic


def load_func(input_f):
    global addr_dic
    global pb_ref
    f = open(input_f, 'r')
    for line in f:
        list_file = str(line).split(':')
        b_file = list_file[0]
        b_file = b_file.replace('@', '/')[1:]
        
        name = b_file.split('/')[-1]
        pb_name = 'Blocks-dyninstEhframe-' + name
        ref_name = 'gtRef_' + name
        ref_name = ref_name + '.pb'
        ref_file = b_file.replace(name, ref_name)
        if '_m32' in b_file:
            b_file = b_file.replace('_m32', '_strip_m32')
        else:
            b_file = b_file.replace('_O', '_strip_O')
        b_file = b_file +'.strip.pb'
        b_file = b_file.replace(name, pb_name)
        addr = list_file[-1]
        addr = addr.split(' ')[2]
        addr = int(addr, 16)
        # correspond pb file to ref file
        if b_file not in pb_ref.keys():
            pb_ref[b_file] = ref_file
        
        # correspond pb file with error
        if b_file in addr_dic.keys():
            addr_dic[b_file].append(addr)
        else:
            addr_dic[b_file] = [addr]

        #print(b_file, addr)
    
def compare_func():
    global addr_dic
    global pb_ref
    t_size = 0
    t_count = 0
    m_count = 0
    for key in addr_dic.keys():
        try:
            f = open(key, 'rb')
            rf = open(pb_ref[key], 'rb')
            mModule = blocks_pb2.module()
            refInf = refInf_pb2.RefList()
            refInf.ParseFromString(rf.read())
            mModule.ParseFromString(f.read())
        except:
            print('No file name: ', key)
            continue
        #if 'libc' in key:
        #    continue
        func_set = func_addr(mModule)
        target_set = tar_addr(refInf)
        print(key)
        count = 0
        count2 = 0
        t_size += len(addr_dic[key])
        for addr in addr_dic[key]:
            #if addr in func_set:    
            #    count += 1
            #else:
                #print(hex(addr))
            if addr not in func_set:
                #count2 += 1
            
                if addr in target_set.keys():
                    count += 1
                    print('Target: ', hex(addr), ', Refer: ', hex(target_set[addr]))
                else:
                    print(hex(addr))
        t_count += count
        m_count += count2
        #if 'openssl' in key:
            #print(key)
        print('Total number: ', len(addr_dic[key]), ' Count Number: ', count)
            #exit()
    print('Total: ', t_size, 'Miss: ', m_count, 'Count: ', t_count)


if __name__ == "__main__":
    options = parse_argument()
    path = options.input
    f = open("/tmp/pbTest.pb", "rb")
    mModule = blocks_pb2.module()
    mModule.ParseFromString(f.read())
    fuc_set = func_addr(mModule)
    print(len(fuc_set))
    #compare_func()
    #f = open('/data/testsuite/libs/gcc_O2/libc', 'rb')
    #mModule1 = blocks_pb2.module()
    #mModule.ParseFromString(f.read())

