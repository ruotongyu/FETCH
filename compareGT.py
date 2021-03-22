import optparse 
#import refInf_pb2
from elftools.elf.elffile import ELFFile



def readSection(binary):
    with open(binary, 'rb') as openFile:
        elffile = ELFFile(openFile)
        res = {}
        for sec in elffile.iter_sections():
            if sec.name == '.text' or sec.name == '.plt' or sec.name == '.init' or sec.name == '.fini':
                start_addr = sec['sh_addr']
                end_addr = sec['sh_addr'] + sec['sh_size']
                res[start_addr] = end_addr
        return res


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("-b", "--binary", type="string", help="binary file path", default=None)

    (options, args) = parser.parse_args()
    
    section_region = readSection(options.binary)   
    for key in section_region.keys():
        print(hex(key), " ", hex(section_region[key]))


