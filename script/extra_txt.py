


if __name__ == "__main__":
    f = open('/home/binpang/Desktop/dyninst/Result/utils.fn', 'r')
    eh_num = 0
    func_num = 0
    for line in f:
        string = str(line).split(" ")
        if len(string) > 7:
            if string[2] == "Functions":
                func_num += int(string[7].strip())
            if string[5] == "raw":
                eh_num += int(string[8].strip())
    print("Total number of functions:", func_num)
    print("Total number of functions identified in eh:", eh_num)




