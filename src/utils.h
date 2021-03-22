#ifndef EH_FRAME_UTILS_H
#define EH_FRAME_UTILS_H
using namespace Dyninst;
using namespace SymtabAPI;
using namespace std;
using namespace InstructionAPI;
using namespace Dyninst::ParseAPI;


void FilterNotInCode(set<uint64_t> &identified, vector<SymtabAPI::Region *> regs);

bool InvalidBB(ParseAPI::Block*);

bool CallingConvensionCheck(ParseAPI::Function* f);
void PrintFuncResult(int raw_eh_num, int reu_eh_num, int gt_num);

void DebugDisassemble(Dyninst::ParseAPI::CodeObject &codeobj);

void getFunctions(set<uint64_t> identified, set<uint64_t> fn_functions, set<uint64_t> &undetect, set<uint64_t> &fixed);

void PrintRefInGaps(set<uint64_t> fnInGap, map<uint64_t, uint64_t> gt_ref, map<uint64_t, uint64_t> &withRef);

void functionInGaps(set<uint64_t> fn_functions, set<uint64_t> &fnInGap, set<uint64_t> &fnNotGap, map<uint64_t, uint64_t> gap_regions);

void printSet(set<uint64_t> p_set);

void printMap(map<uint64_t, uint64_t> p_map);

bool isInGaps(map<unsigned long, unsigned long> gap_regions, unsigned ref);

void Target2Addr(map<uint64_t, uint64_t> gt_ref, set<uint64_t> fn_functions);

set<uint64_t> compareFunc(set<uint64_t> eh_functions, set<uint64_t> gt_functions, bool flag);

void unionSet(set<Address> set1, set<Address> &set2);

void ScanAddrInGap(map<uint64_t, uint64_t> gap_regions, set<Address> dataRef, set<Address> &RefinGap);

class nopVisitor : public InstructionAPI::Visitor{
	public:
		nopVisitor() : foundReg(false), foundImm(false), foundBin(false), isNop(true){}
		virtual ~nopVisitor();

		bool foundReg;
		bool foundImm;
		bool foundBin;
		bool isNop;

		virtual void visit(BinaryFunction*);

		virtual void visit(Immediate *imm);
			
		virtual void visit(RegisterAST *);

		virtual void visit(Dereference *);
};

bool isNopInsn(Instruction insn);


void ScanGaps(map<uint64_t, uint64_t> gap_regions, map<uint64_t, uint64_t> scanTarget);

map<uint64_t, uint64_t> getGaps(map<uint64_t, uint64_t> functions, vector<SymtabAPI::Region *> regs, uint64_t &gap_regions_num);
#endif
