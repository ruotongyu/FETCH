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

def dumpAddr(addr_dict):
    total = 0
    exit_func = 0
    bad = 0
    log_assert = 0
    other = 0
    catch_end = 0
    for key in addr_dict.keys():
        sort_addr = sorted(addr_dict[key])
        file_addr = key[1:].replace("@", "/").strip()
        objdump_command = "objdump -d " + file_addr + " > /tmp/tmp_res.dump"
        if "libs" in objdump_command or len(sort_addr) == 0:
            continue
        os.system(objdump_command)
        print(objdump_command)
        dump_file = open('/tmp/tmp_res.dump', 'r')
        index = 0
        flag = 0
        res_dict = {}
        total += len(sort_addr)
        for line in dump_file:
            last_char = ''
            if index >= len(sort_addr):
                break
            if len(line) > 1:
                last_char = str(line).strip()[-1]
            if last_char == ":":
                fuc_string = str(line).split(' ')[0]
                try:
                    fuc_addr = int(fuc_string, 16)
                except:
                    continue
                
                if flag == 1:
                    res_dict[sort_addr[index]] = 0
                    index+=1
                    if index >= len(sort_addr):
                        break
                    if int(sort_addr[index], 16) != fuc_addr:
                        flag = 0
                else:
                    if int(sort_addr[index], 16) == fuc_addr:
                        flag = 1

            if flag == 1:
                if "Unwind_Resume" in str(line) or "abort" in str(line) or "ud2" in str(line) or "terminate" in str(line) or "assertion_failed" in str(line) or "throw_bad" in str(line):
                    res_dict[sort_addr[index]] = 1
                    index+=1
                    flag = 0
                #elif "throw_bad" in str(line):
                #    res_dict[sort_addr[index]] = 2
                #    index+=1
                #    flag = 0
                elif "log_failed_assert" in str(line) or "log_error_write" in str(line):
                    res_dict[sort_addr[index]] = 3
                    index+=1
                    flag = 0
                #elif "cxa_end_catch" in str(line):
                #    res_dict[sort_addr[index]] = 4
                #    index+=1
                #    flag = 0
            
        
        for key in res_dict.keys():
            if res_dict[key] == 1:
                exit_func += 1
            if res_dict[key] == 2:
                bad += 1
                print(key, res_dict[key], " Bad")
            if res_dict[key] == 3:
                log_assert+=1
                print(key, res_dict[key], " assert")
            if res_dict[key] == 4:
                catch_end += 1
                print(key, res_dict[key], " catch_end")
            if res_dict[key] == 0:
                other += 1
                print(key, res_dict[key], " Other")
            
    print("Total: ", total, "Exit func: ", exit_func, " Throw Bad: ", bad, " assert", log_assert, " other: ", other)


if __name__ == "__main__":
    options = parse_argument()
    path = options.input
    addr_dict = readLog()
    dumpAddr(addr_dict)
