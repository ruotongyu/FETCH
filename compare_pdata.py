import optparse
import logging
from PEUtil import *

def parseFuncsFromExcInfo(binary):
    rand_output = randomString()
    cmd = "llvm-objdump -u %s | grep 'Start Address:' > /tmp/%s" % (binary, rand_output)
    rm_cmd = "rm /tmp/%s" % (rand_output)
    result = set()
    try:
        os.system(cmd)
    except:
        logging.error("Parsing .pdata error!")
        os.system(rm_cmd)
        return result

    with open('/tmp/%s' % (rand_output), 'r') as exc_funcs:
        for line in exc_funcs:
            cur_func = int(line.split(' ')[-1], 16)
            logging.debug("Exc Info Func: 0x%x" % cur_func)
            result.add(cur_func)
    os.system(rm_cmd)
    return result

def compare_funcs(sym_funcs, exc_funcs):
    fp = exc_funcs.difference(sym_funcs)
    fn = sym_funcs.difference(exc_funcs)

    fp_idx = 0
    fn_idx = 0

    for f in fp:
        logging.info("FP #%d: 0x%x" % (fp_idx, f))
        fp_idx += 1

    for f in fn:
        logging.info("FN #%d: 0x%x" % (fn_idx, f))
        fn_idx += 1

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action = "store", \
            type = "string", help = "binary file", default = None)
    parser.add_option("-p", "--pdb", dest = "pdb", action = "store", \
            type = "string", help = "pdb file", default = None)

    (options, args) = parser.parse_args()

    assert options.binary != None, "Please input binary file with(-b)!"
    assert options.pdb != None, "Please input pdb file with(-p)!"

    secs = parsePESecs(options.binaryfile)
    (image_base, _) = parsePEFile(options.binaryfile)

    symbol_funcs = parseFuncs(options.pdb, secs, image_base)
    exc_funcs = parseFuncsFromExcInfo(options.binaryfile)
    compare_funcs(symbol_funcs, exc_funcs)
