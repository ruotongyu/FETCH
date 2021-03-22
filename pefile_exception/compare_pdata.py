import optparse
import logging
from PEUtil import *

logging.basicConfig(level = logging.INFO)

def parseFuncsFromExcInfo(binary, image_base):
    rand_output = randomString()
    cmd = "llvm-objdump -u %s > /tmp/%s" % (binary, rand_output)
    rm_cmd = "rm /tmp/%s" % (rand_output)
    result = set()
    try:
        os.system(cmd)
    except:
        logging.error("Parsing .pdata error!")
        os.system(rm_cmd)
        return result

    last_func_addr = 0x0
    with open('/tmp/%s' % (rand_output), 'r') as exc_funcs:
        for line in exc_funcs:
            if 'Start Address:' in line:
                last_func_addr = int(line.split(' ')[-1], 16) + image_base
                continue

            if 'Flags' in line:
                if 'UNW_ChainInfo' in line:
                    last_func_addr = 0x0
                else:
                    logging.debug("Exc Info Func: 0x%x" % last_func_addr)
                    result.add(last_func_addr)
    os.system(rm_cmd)
    return result

def compare_funcs(sym_funcs, exc_funcs, thunk_funcs):
    fp = exc_funcs.difference(sym_funcs)
    fn = sym_funcs.difference(exc_funcs)

    fp_idx = 0
    fn_idx = 0

    for f in fp:
        if f in thunk_funcs:
            continue
        logging.info("FP #%d: 0x%x" % (fp_idx, f))
        fp_idx += 1

    for f in fn:
        logging.info("FN #%d: 0x%x" % (fn_idx, f))
        fn_idx += 1

    logging.info("Summary: functions in symbols: %d" % len(sym_funcs))
    logging.info("Summary: functions in exception info: %d" % len(exc_funcs))
    logging.info("Summary: FN is %d" % fn_idx)
    logging.info("Summary: FP is %d" % fp_idx)

if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", dest = "binary", action = "store", \
            type = "string", help = "binary file", default = None)
    parser.add_option("-p", "--pdb", dest = "pdb", action = "store", \
            type = "string", help = "pdb file", default = None)

    (options, args) = parser.parse_args()

    assert options.binary != None, "Please input binary file with(-b)!"
    assert options.pdb != None, "Please input pdb file with(-p)!"

    secs = parsePESecs(options.binary)
    (image_base, _) = parsePEFile(options.binary)

    thunk_funcs = parseThunkSyms(options.pdb, secs, image_base)
    symbol_funcs = parseFuncs(options.pdb, secs, image_base)
    exc_funcs = parseFuncsFromExcInfo(options.binary, image_base)
    compare_funcs(set(symbol_funcs.keys()), exc_funcs, thunk_funcs)
