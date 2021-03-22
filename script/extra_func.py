


def readFunc(input_file):
    f = open(input_file, 'r')
    func_dic = {}
    file_name = ""
    for line in f:
        line_str = str(line)
        if line_str[0:5] == "/data":
            file_name = line_str.strip()
        if line_str[0:5] == "Targe":
            func_str = line_str.split(" ")[2].strip()
            func_addr = int(func_str, 16)
            if file_name not in func_dic.keys():
                func_dic[file_name] = [func_addr]
            else:
                tmp = func_dic[file_name]
                tmp.append(func_addr)
    return func_dic

def readEhFunc(input_file):
    f = open(input_file, 'r')
    func_dic = {}
    file_name = ""
    for line in f:
        line_str = str(line)
        if line_str[0:5] == "/data":
            file_name = line_str.strip()
        if line_str[0:5] == "Targe":
            func_str = line_str.split(" ")[1].strip()
            func_addr = int(func_str, 16)
            if file_name not in func_dic.keys():
                func_dic[file_name] = [func_addr]
            else:
                tmp = func_dic[file_name]
                tmp.append(func_addr)
    return func_dic

def compareFunc(dic1, dic2):
    for key in dic1.keys():
        print(key)
        for addr in dic1[key]:
            if addr not in dic2[key]:
                print("Not found", hex(addr))

if __name__ == "__main__":
    fn_dic = readFunc("fn_with_reference.log")
    eh_dic = readEhFunc("ehframe_all_func.log")
    compareFunc(fn_dic, eh_dic)
