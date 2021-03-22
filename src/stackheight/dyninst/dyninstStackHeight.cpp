/* Reference: https://github.com/trailofbits/mcsema/blob/master/tools/mcsema_disass/dyninst/
 * Date: 10/10/2019
 * Author: binpang
 *
 * Extract the cfg from dyninst
 *
 * Build: make
 */

#include <stdio.h>
#include <sstream>
#include <fstream>
#include <set>
#include <cstdint>

#include "CodeObject.h"
#include "Function.h"
#include "Symtab.h"
#include "Instruction.h"
#include "stackanalysis.h"


#include "glog/logging.h"
#include "gflags/gflags.h"

#include "stackheight.pb.h"

#include <sstream>
#include <string>

//#define LIVENESS_ANALYSIS
#define STACK_ANALYSIS
#define STACK_ANALYSIS_DEBUG

// for liveness analysis
#include "Location.h"
#include "livenessAnaEhframe.h"
#include "bitArray.h"

using namespace Dyninst;
DEFINE_string(binary, "", "Path to striped binary file");
DEFINE_string(output, "/tmp/StackHeight_dyninst.pb", "Path to output file");
DEFINE_int32(speculative, 1, "The mode of speculative parsing. 0 represents do not parse. 1 represents using idiom, 2 represents using preamble, 3 represents using both. default is 1");
std::set<uint64_t> matchingFunc;
int total_funcs = 0;

#ifdef LIVENESS_ANALYSIS

// blacklist
// ds, es, fs, gs, cs, ss
bool DebugBitArr(uint64_t addr, std::map<MachRegister,int>* regs_map, const bitArray& b_arr){
    bool has_undef_regs = false;
    std::set<std::string> segment_list = {"es", "fs", "ds", "gs", "cs", "ss"};

    for (auto item : *regs_map){
	if(b_arr[item.second] && !item.first.isPC() && !item.first.isStackPointer() && 
		segment_list.find(item.first.name()) != segment_list.end()){
	    DLOG(INFO) << "func : " << addr << ",  reg:" << item.first.name() << std::endl;
	    has_undef_regs = true;
	}
    }

    return has_undef_regs;
}

void LivenessAnalysis(ParseAPI::Function* f){
    EHFrameAna::LivenessAnalyzer la(f->obj()->cs()->getAddressWidth());

    ABI* abi = la.getABI();

    bitArray callread_regs = abi->getCallReadRegisters();

    bitArray liveEntry;

    // construct a liveness query location
    ParseAPI::Location loc(f, f->entry());


    if (la.query(loc, EHFrameAna::LivenessAnalyzer::Before, liveEntry)){
	liveEntry -= callread_regs;
	if (liveEntry.size() > 0){
	    DebugBitArr(f->addr(), abi->getIndexMap(), liveEntry);
	}
    }
}

void traverseLiveness(ParseAPI::CodeObject &codeobj){
    std::set<Dyninst::Address> seen;
    for(auto func: codeobj.funcs()){
	if (seen.count(func->addr()))
	  continue;
	LivenessAnalysis(func);
    }
}
#endif

void StackHeight(stackheight::StackHeights& sh_proto, Dyninst::ParseAPI::Function* func){
    // Get the address of the first instruction of the block
    // Get the stack heights at that address
    signed long height_num = 0;
    std::stringstream ss;
    Dyninst::StackAnalysis sa(func);
    for (auto block: func->blocks()){
	uint64_t addr = 0;
	auto cur_ret = block->getInsn(addr);
        ParseAPI::Block::Insns instructions;
	block->getInsns(instructions);

      // get instructions
      for(auto p: instructions){
	//if (cur_ret.getCategory() != InstructionAPI::c_ReturnInsn) continue;
	addr = p.first;
	
#ifdef STACK_ANALYSIS_DEBUG
	DLOG(INFO) << "[StackHeight]: current block is 0x" << std::hex << addr << std::endl;
#endif

	// Print out the stack heights
	std::vector<std::pair<Dyninst::Absloc, Dyninst::StackAnalysis::Height>> heights;
	sa.findDefinedHeights(block, addr, heights);
	for (auto iter = heights.begin(); iter != heights.end(); iter++) {
	    const Dyninst::Absloc &loc = iter->first;
	    if (!loc.isSP()){
		continue;
	    }
	    const Dyninst::StackAnalysis::Height &height = iter->second;
	    if (height.isTop()){
		height_num = 0xdeadbeef; // magic number to represent the "TOP" in dyninst
	    } else if (height.isBottom()){
		height_num = 0xffffffff; // magic number to represent the "BOTTOM" in dyninst
	    } else {
		//height_num = 
		ss << height;
		ss >> height_num;
		height_num = height_num * -1;
		ss.clear();
	    }
	    auto cur_height = sh_proto.add_heights();
	    cur_height->set_address(addr);
	    cur_height->set_height(height_num);
#ifdef STACK_ANALYSIS_DEBUG
	    DLOG(INFO) << loc.format().c_str() << " := " << height_num << std::endl;
#endif
	}
      }
    }
}

void traverseStackHeights(stackheight::StackHeights& sh_proto, Dyninst::ParseAPI::CodeObject &codeobj){
  std::set<Dyninst::Address> seen;
  // Set to record the function matching functions
  for (auto func: codeobj.funcs()){
    if (seen.count(func->addr()))
      continue;
    StackHeight(sh_proto, func);
    }
  }


std::string getRandomString(int n){
        char alphabet[26] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
        std::string res = "";
        for (int i = 0; i < n; i++){
                res = res + alphabet[rand() % 26];
        }
        return res;
}

void getEhFramePcAddrs(std::set<uint64_t>& pc_sets, const char* input){

  std::stringstream ss;
  std::string rs = getRandomString(10);
  std::string output("/tmp/"+rs);

  ss << "readelf --debug-dump=frames " << input << " | grep pc | cut -f3 -d = | cut -f1 -d . > /tmp/" << rs;

  system(ss.str().c_str());

  std::ifstream frame_file(output.c_str());
  std::string line;

  if (frame_file.is_open()){

    while(std::getline(frame_file, line)){

        uint64_t pc_addr = std::stoul(line, nullptr, 16);

        pc_sets.insert(pc_addr);

        }
  }

  ss.clear();

  ss << "rm " << "/tmp/" << rs;
  system(ss.str().c_str());
}

int main(int argc, char** argv){

  std::stringstream ss;
  stackheight::StackHeights sh_proto;
  ss << " " << argv[0] << "\\" << std::endl
    << "      --binary INPUT_FILE \\" << std::endl
    << "      --output OUTPUT PB FILE \\" << std::endl
    << "      --speculative SPECULATIVE MODE \\" << std::endl
    << "      --statics STATICS DATA" << std::endl;

  FLAGS_logtostderr = 1;
  // Parse the command line arguments
  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);
  CHECK(!FLAGS_binary.empty()) << "Input file need to be specified!";
  LOG(INFO) << "Config: binary path " << FLAGS_binary << "\n"
    << "output file is " << FLAGS_output << "\n"
    << "speculative mode is " << FLAGS_speculative << "\n" << std::endl;
  
  auto input_string = FLAGS_binary.data();
  auto input_file = const_cast<char* >(input_string);
  auto symtab_cs = std::make_shared<ParseAPI::SymtabCodeSource>(input_file);
  CHECK(symtab_cs) << "Error during creation of ParseAPI::SymtabCodeSource!";


  auto code_obj = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
  CHECK(code_obj) << "Error during creation of ParseAPI::CodeObject";

  std::set<uint64_t> pc_sets;
  getEhFramePcAddrs(pc_sets, input_string);

  code_obj->parse();
  
  std::set<uint64_t> handled;
  for(auto addr: pc_sets){
    //DLOG(INFO) << "start recursive at " << std::hex << addr << "\n";
    code_obj->parse(addr, true);
  }

  traverseStackHeights(sh_proto, *code_obj);

#ifdef LIVENESS_ANALYSIS
  traverseLiveness(*code_obj);
#endif

  auto output_file = const_cast<char* >(FLAGS_output.data());
  std::fstream output(output_file, std::ios::out | std::ios::trunc | std::ios::binary);
  // save the protobuf file
  if (!sh_proto.SerializeToOstream(&output)) {
    LOG(FATAL) << "Failed to write the address block" << std::endl;
    return -1;
  }

  output.close();
  return 0;
}
