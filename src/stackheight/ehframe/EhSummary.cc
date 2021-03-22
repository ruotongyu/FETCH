#include <iostream>
#include <fstream>
#include <sstream>
#include <set>

#include "EhframeParser.h"

#include "glog/logging.h"
#include "gflags/gflags.h"

#include "stackheight.pb.h"
#include "blocks.pb.h"

using namespace std;

DEFINE_string(binary, "", "Path to striped binary file");

int main(int argc, char** argv){

    signed height;
    FrameParser *fp = 0; 
    stringstream ss;

    ss << " " << argv[0] << "\\" << endl 
	<<  "	--binary BINARY_FILE \\ " << endl;

    FLAGS_logtostderr = 1;
    FLAGS_minloglevel = 0;

    // parse the command line arguments
    google::InitGoogleLogging(argv[0]);
    google::SetUsageMessage(ss.str());
    google::ParseCommandLineFlags(&argc, &argv, true);

    CHECK(!FLAGS_binary.empty()) << "Input binary file need to be specified!";

    LOG(INFO) << "Config: binary path " << FLAGS_binary << endl;

    fp = new FrameParser(FLAGS_binary.data());
    fp->summary();
    delete fp;
}
