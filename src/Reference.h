#include <stdio.h>
#include <sstream>
#include <fstream>
#include <set>
#include <cstdint>
#include "CodeObject.h"
#include "Function.h"
#include "Symtab.h"
#include "Instruction.h"
#include "glog/logging.h"
#include "gflags/gflags.h"
#include <sys/stat.h>
#include <iostream>
#include <capstone/capstone.h>
#include <Dereference.h>
#include "protobuf/blocks.pb.h"
#include "Location.h"
#include "livenessAnaEhframe.h"
#include "bitArray.h"

using namespace Dyninst;
using namespace SymtabAPI;
using namespace std;
using namespace InstructionAPI;
using namespace Dyninst::ParseAPI;

map<uint64_t, uint64_t> CCReference(Dyninst::ParseAPI::CodeObject &codeobj, vector<SymtabAPI::Region *>& code_regs, set<unsigned> &instructions);

map<uint64_t, uint64_t> DCReference(vector<SymtabAPI::Region *>& data_regs, vector<SymtabAPI::Region *>& code_regs, uint64_t offset, char* input, char* x64, set<unsigned> &instructions);

map<uint64_t, uint64_t> DDReference(vector<SymtabAPI::Region *>& regs, uint64_t offset, char* input, char* x64);

map<uint64_t, uint64_t> CDReference(Dyninst::ParseAPI::CodeObject &codeobj, vector<SymtabAPI::Region *>& code_regs, set<unsigned> &instructions, vector<SymtabAPI::Region *>& data_regs);

void getDataReference(std::vector<SymtabAPI::Region *>& regs, uint64_t offset, char* input, char* x64, map<uint64_t, uint64_t> &RefMap);

void getCodeReference(Dyninst::ParseAPI::CodeObject &codeobj, map<uint64_t, uint64_t> &RefMap);

bool isCFInst(InstructionAPI::Instruction* ins);
