


if __name__ == "__main__":
    #f = open('/home/binpang/Desktop/Result/clients.fn_notailcall_x64', 'r')
    f = open('/tmp/angrSymbol.utils')
    full_cover_num = 0
    file_num = 0
    gt_function = 0
    fn_function = 0
    fp_function = 0
    for line in f:
        string = str(line).split(" ")
        if "Result" in line:
            if string[1] == "negitive" and int(string[4].strip()) > 0:
                full_cover_num += 1
                fn_function += int(string[4].strip())
            if len(string) > 7 and string[4] == "ground":
                gt_function += int(string[7].strip())
            if string[1] == "positive":
                fp_function += int(string[4].strip())
        if "Handle" in line:
            file_num += 1
    print("Total number of functions:", gt_function)
    print("Total number of File:", file_num)
    print("Total number of full cover file:", full_cover_num)
    print("Total number of FN Function:", fn_function)
    print("Total number of FP Function:", fp_function)


