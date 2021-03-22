
if __name__ == "__main__":
    f = open('/tmp/dyninst_servers.log', 'r')
    #O0, O2, O3, Os, Of
    # true positive, false positve, unknown, false negative 
    dic = {"gcc_O1":0, "gcc_O2":1, "gcc_O3":2, "gcc_Os":3, "gcc_Of":4, "gcc_m32_O1":5, "gcc_m32_O2":6, "gcc_m32_O3":7, "gcc_m32_Os":8, "gcc_m32_Of":9}
    opt_dict = []
    for i in range(10):
        opt_dict.append([0, 0, 0, 0, 0])
    index = -2
    for line in f:
        string = str(line).split(" ")
        if len(string) > 3:
            if string[2] == "is":
                index = dic[string[3].strip()]
            if string[2] == "True":
                opt_dict[index][0] += int(string[4].strip())
            if string[2] == "False":
                opt_dict[index][1] += int(string[4].strip())
            if string[2] == "Unknown":
                opt_dict[index][2] += int(string[3].strip())
            if string[2] == "Num":
                opt_dict[index][3] += int(string[3].strip())
            if string[2] == "Tool":
                opt_dict[index][4] += int(string[4].strip())

    for key in dic:
        print("Result for", key)
        print("Total number of TP:", opt_dict[dic[key]][0])
        print("Total number of FP:", opt_dict[dic[key]][1])
        print("Total number of unknown:", opt_dict[dic[key]][2])
        print("Total number of Ehframe missing:", opt_dict[dic[key]][3])
        print("Total number of dyninst missing:", opt_dict[dic[key]][4])
        print("<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>")
        print("<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>")




