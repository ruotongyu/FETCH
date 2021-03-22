#ifndef EH_FRAME_LOAD_H
#define EH_FRAME_LOAD_H
using namespace Dyninst;
using namespace SymtabAPI;
using namespace std;
using namespace InstructionAPI;
using namespace Dyninst::ParseAPI;


void getEhFrameAddrs(std::set<uint64_t>& pc_sets, const char* input, map<uint64_t, uint64_t> &functions);


void loadFnAddrs(char* input, map<uint64_t, uint64_t> &ref2func);
#endif
