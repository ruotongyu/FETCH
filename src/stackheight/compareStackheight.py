from ./proto import stackheight_pb2

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

import logging
import optparse

def compare_result(ehframe, comapred):
    with open(eh_frame, 'rb') as ehframe_bin:
        height_frame = stackheight_pb2.StackHeights()

if __name__ == "__main__":
    parser = opatparse.OptionParser()
    parser.add_option("-e", "--ehframe", dest = "ehframe", action = "store", type = "string", \
            help = "the path of protobuf generated based on ehframe", default = None)
    parser.add_option("-c", "--compared", dest = "compared", action = "store", type = "string", \
            help = "the path of compared protobuf", default = None)

    (options, args) = parser.parse_args()

    assert options.ehframe != None, "Please input the path of protobuf generated based on ehframe!"
    assert options.compared != None, "Please input the path of compared protobuf!"
