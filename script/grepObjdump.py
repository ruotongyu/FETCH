import os


def readAddr(File):
    f = open(File, 'r')
    addr_list = []
    for line in f:
        str_line = str(line)
        str_addr = str_line.split(" ")[3]
        addr_list.append(str_addr)
    return addr_list

def grepObjRes(addr_list):
    functions = []
    for addr in addr_list:
        command = "grep \"" + addr + "\" /tmp/openssl.dump | grep \">:\" > /tmp/func.tmp"
        os.system(command)
        f1 = open("/tmp/func.tmp", 'r')
        for line in f1:
            name = str(line).split(" ")[1].strip()
            functions.append(name[1:len(name)-2])
    return functions

if __name__ == "__main__":
    
    addr_list = readAddr("/tmp/tmp.log")
    functions = grepObjRes(addr_list)
    for fuc in functions:
        print(fuc)
