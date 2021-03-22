


if __name__ == "__main__":
    #f = open('/home/binpang/Desktop/Result/utils_fp_notailcall_x64', 'r')
    f = open('/tmp/gt_ehres_servers.fp')
    eh_num = 0
    func_num = 0
    jumpNum = 0
    total = 0
    for line in f:
        string = str(line).split(" ")
        if len(string) > 7:
            if string[4] == "ground":
                total += int(string[7].strip())
            if string[5] == "EhFrame" and string[6] == "Disassembling":
                eh_num += int(string[8].strip())
            if string[5] == "Reference":
                func_num += int(string[8].strip())
    print("Total number of functions", total)
    print("Total number of fp functions in reference:", func_num)




