


if __name__ == "__main__":
    #f = open('/home/binpang/Desktop/Result/utils_fp_notailcall_x64', 'r')
    f = open('/tmp/tailcall_libs.fp_Of')
    eh_num = 0
    func_num = 0
    jumpNum = 0
    total = 0
    file_num = 0
    tmp = True
    for line in f:
        string = str(line).split(" ")
        #if "Handle File" in str(line): 
            #if "_O2" in str(line):    
            #    tmp = True
            #else:
            #    tmp = False
        if len(string) > 7:
            if string[4] == "ground" and tmp:
                total += int(string[7].strip())
            if string[5] == "EhFrame" and string[6] == "Disassembling" and tmp:
                eh_num += int(string[8].strip())
            if string[5] == "Reference" and tmp:
                file_num += 1
                func_num += int(string[8].strip())
            if string[6] == "TailCall" and string[7] == "is" and tmp:
                jumpNum += int(string[8].strip())
    print("Total number of functions", total)
    print("Total number of fp functions in ehframe:", eh_num)
    print("Total number of fp functions in reference:", func_num)
    print("Total number of fp functions not in ehframe:", jumpNum)
    print("Total number of File:", file_num)




