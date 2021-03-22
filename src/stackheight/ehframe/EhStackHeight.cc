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
DEFINE_string(output, "/tmp/dyninst_stackheight.pb", "Path ot output file");
DEFINE_string(instrpb, "", "Path to instructions pb file");

void dumpStackHeight(const char* binary_path, const char* inst_pb, const char* output){

    set<uint64_t> seen;
    stackheight::StackHeights sh_proto;
    blocks::module pb_proto;
    signed height;
    FrameParser *fp = new FrameParser(binary_path);
    fstream inst_file = fstream(inst_pb, ios::in | ios::binary);
    fstream out_file = fstream(output, ios::out | ios::binary | ios::trunc);

    if (!pb_proto.ParseFromIstream(&inst_file)){
	LOG(ERROR) << "Can't parse instruction proto " << inst_pb << endl;
	delete fp;
	return;
    }

    for (int f_i = 0; f_i < pb_proto.fuc_size(); f_i++){
	auto cur_func = pb_proto.fuc(f_i);

	if (seen.count(cur_func.va())){
	    continue;
	 }
	seen.insert(cur_func.va());

	for (int b_i = 0; b_i < cur_func.bb_size(); b_i++){
	    auto cur_bb = cur_func.bb(b_i);

	    for (int i_i = 0; i_i < cur_bb.instructions_size(); i_i++){
		auto cur_addr = cur_bb.instructions(i_i).va();
		auto res = fp->request_stack_height(cur_addr, height);
		if(!res){
		    LOG(INFO) << "stack heigth at " << hex << cur_addr << " : " << dec << height << endl;
		    auto cur_height = sh_proto.add_heights();
		    cur_height->set_address(cur_addr);
		    cur_height->set_height(height);
		} 
	    }
	}
    }

    if (!sh_proto.SerializeToOstream(&out_file)){
	    cout << "error!" << endl;
	LOG(FATAL) << "Failed to write proto " << output << endl;
	delete fp;
	return;
    }
    out_file.close();
    delete fp;
}

int main(int argc, char** argv){

    signed height;
    FrameParser *fp = 0; 
    stringstream ss;

    ss << " " << argv[0] << "\\" << endl 
	<<  "	--binary BINARY_FILE \\ " << endl
	<<  "	--output OUTPUT PB FILE \\ " << endl
	<<  "	--instpb INSTRUCTIONS PB FILE \\" << endl;

    FLAGS_logtostderr = 1;
    FLAGS_minloglevel = 0;

    // parse the command line arguments
    google::InitGoogleLogging(argv[0]);
    google::SetUsageMessage(ss.str());
    google::ParseCommandLineFlags(&argc, &argv, true);

    CHECK(!FLAGS_binary.empty()) << "Input binary file need to be specified!";
    CHECK(!FLAGS_instrpb.empty()) << "Input instruction pb file need to be specified!";

    LOG(INFO) << "Config: binary path " << FLAGS_binary << "\n" 
	<< " instruction pb path " << FLAGS_instrpb << "\n"
	<< " output path is " << FLAGS_output << endl;

    dumpStackHeight(FLAGS_binary.data(), FLAGS_instrpb.data(), FLAGS_output.data());
}
