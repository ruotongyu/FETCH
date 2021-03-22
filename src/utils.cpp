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
#include "protobuf/refInf.pb.h"
#include "protobuf/blocks.pb.h"

// for liveness analysis
#include "Location.h"
#include "livenessAnaEhframe.h"
#include "bitArray.h"

using namespace Dyninst;
using namespace std;
using namespace InstructionAPI;
using namespace Dyninst::ParseAPI;
#define LIVENESS_DEBUG

//#define DEBUG

bool isMMXRegs(int regClass){
    return 0 != (regClass & x86::MMX);
}
// blacklist
// ds, es, fs, gs, cs, ss
bool CheckUndefRegs(uint64_t addr, std::map<MachRegister,int>* regs_map, const bitArray& b_arr){
    bool has_undef_regs = false;

    for (auto item : *regs_map){
	if(b_arr[item.second] && !item.first.isPC() && !item.first.isStackPointer() \
	                    && !item.first.isFlag() && !isSegmentRegister(item.first.regClass())){
#ifdef LIVENESS_DEBUG
	    cout << "[undef reg]: func : " << addr << ",  reg:" << item.first.name() << std::endl;
#endif
	    has_undef_regs = true;
	}
    }

    return has_undef_regs;
}

void debugStackHeight(uint64_t addr, std::map<MachRegister,int>* regs_map, const bitArray& b_arr){

    for (auto item : *regs_map){
	if(b_arr[item.second] && !item.first.isPC() && !item.first.isStackPointer() \
	                    && !item.first.isFlag() && !isSegmentRegister(item.first.regClass())){
#ifdef LIVENESS_DEBUG
	    cout << "[debug reg]: bb : " << addr << ",  reg:" << item.first.name() << std::endl;
#endif
	}
    }
}

void debugLiveness(ParseAPI::Function *f){
    EHFrameAna::LivenessAnalyzer la(f->obj()->cs()->getAddressWidth());

    ABI* abi = la.getABI();

    bitArray callread_regs = abi->getCallReadRegisters();

    bitArray liveEntry;

    // construct a liveness query location
    for ( auto b : f->blocks()){
	    ParseAPI::Location loc(f, f->entry());

	    if (la.query(loc, EHFrameAna::LivenessAnalyzer::Before, liveEntry)){
		liveEntry -= callread_regs;
		if (liveEntry.size() > 0){
		    debugStackHeight(b->start(), abi->getIndexMap(), liveEntry);
		}
	    }
    }
}

// return true if it can pass the check of calling convension
bool CallingConvensionCheck(ParseAPI::Function* f){

    EHFrameAna::LivenessAnalyzer la(f->obj()->cs()->getAddressWidth());

    ABI* abi = la.getABI();

    bitArray callread_regs = abi->getCallReadRegisters();

    bitArray liveEntry;

    // construct a liveness query location
    ParseAPI::Location loc(f, f->entry());

    if (la.query(loc, EHFrameAna::LivenessAnalyzer::Before, liveEntry)){
	liveEntry -= callread_regs;
	if (liveEntry.size() > 0){
	    return !CheckUndefRegs(f->addr(), abi->getIndexMap(), liveEntry);
	}
    }
    return true;
}

void FilterNotInCode(set<uint64_t> &identified, vector<SymtabAPI::Region *> regs){
	uint64_t sec_start, sec_end;
	for (auto region : regs){
		if (region->getRegionName() == ".text") {
			sec_start = (uint64_t) region->getMemOffset();
			sec_end = sec_start + region->getMemSize();
		}
	}
	//cout << "start: " << hex << sec_start << " " << sec_end << endl;
	for (auto func: identified){
		if (func >= sec_start && func < sec_end) {
			continue;
		}else{
			identified.erase(func);
		}
	}
}


void PrintFuncResult(int raw_eh_num, int reu_eh_num, int gt_num) {
	cout << "Number of Ground Truth Functions: " << dec << gt_num << endl;
	cout << "Number of Missing Functions from EhFrame: " << dec << raw_eh_num << endl;
	cout << "Number of Missing Functions from Recursive Disassemble EHFrame: " << dec << reu_eh_num << endl;
}

bool InvalidBB(ParseAPI::Block* block){

    ParseAPI::Block::Insns instructions;
    block->getInsns(instructions);
    const unsigned char* buffer_beg;
    Address last_inst = 0x0;

    // does not contain instructions
    if (instructions.begin() == instructions.end()){
	return true;
    } else {
	last_inst = instructions.rbegin()->first;
    }



    // not equal? check if it is caused by decoding error
    if (last_inst != block->last()){
	buffer_beg = (const unsigned char *)
	    (block->obj()->cs()->getPtrToInstruction(block->last()));
	InstructionDecoder dec = InstructionDecoder(
		buffer_beg, InstructionDecoder::maxInstructionLength, block->region()->getArch());

	auto bad_inst = dec.decode();

	if (!bad_inst.isLegalInsn()){
	    return true;
	}
    }

    return false;
}

void DebugDisassemble(Dyninst::ParseAPI::CodeObject &codeobj) {
	set<Address> seen;
	cout << "<<<<<<<<<<<<<<<Debug Result >>>>>>>>>>>>>>>>>" << endl;
	for (auto func:codeobj.funcs()){
		if(seen.count(func->addr())){
			continue;
		}
		seen.insert(func->addr());
		cout << "Function Start: " << hex << func->addr() << endl;
		for(auto block: func->blocks()){
			Dyninst::ParseAPI::Block::Insns instructions;
			block->getInsns(instructions);
			uint64_t cur_addr = block->start();

			if (InvalidBB(block)){
			    cout << "Invalid inst: " << hex << block->last() << endl;
			}

			for (auto it: instructions){
				Dyninst::InstructionAPI::Instruction inst = it.second;
				cout << "Inst: 0x" << hex << cur_addr << " " << inst.format() << endl; 
				cur_addr += inst.size();
			}
		}
	}
}

void getFunctions(set<uint64_t> identified, set<uint64_t> fn_functions, set<uint64_t> &undetect, set<uint64_t> &fixed){
	for (auto fuc: fn_functions){
		if (identified.count(fuc)){
			fixed.insert(fuc);
		} else{
			undetect.insert(fuc);
		}
	}
}

void PrintRefInGaps(set<uint64_t> fnInGap, map<uint64_t, uint64_t> gt_ref, map<uint64_t, uint64_t> &withRef){
	int NoRef = 0;
	for (auto fn : fnInGap){
		if (!gt_ref[fn]){
			NoRef++;
		}else{
			withRef[fn] = gt_ref[fn];
		}
	}
	int WithRef = fnInGap.size() - NoRef;
	cout << "FN in gaps with Ref: " << dec << WithRef << endl;
        cout <<	"FN in gaps without Ref: " << dec << NoRef << endl;
	//for (auto ref: withRef){
	//	cout << "Address: " << hex << ref.first << " Ref:" << ref.second << endl;
	//}
}

void functionInGaps(set<uint64_t> fn_functions, set<uint64_t> &fnInGap, set<uint64_t> &fnNotGap, map<uint64_t, uint64_t> gap_regions) {
	for (auto func: fn_functions){
		bool found = false;
		for (auto gap: gap_regions){
			if (func >= gap.first && func < gap.second){
				fnInGap.insert(func);
				found = true;
				break;
			}
		}
		if (!found) {
			fnNotGap.insert(func);
		}
	}
}


void printSet(set<uint64_t> p_set){
	for (auto ite: p_set){
		cout << hex << ite << endl;
	}
}

void printMap(map<uint64_t, uint64_t> p_map) {
	for (map<uint64_t, uint64_t>::iterator it=p_map.begin(); it!=p_map.end(); ++it){
		cout << hex << it->first << " " << it->second << endl;
	}
}

// Check if the address in gap regions
bool isInGaps(std::map<unsigned long, unsigned long> gap_regions, unsigned ref){
	for(std::map<unsigned long, unsigned long>::iterator ite=gap_regions.begin(); ite!=gap_regions.end();++ite) {
		unsigned long c_addr = (unsigned long) ref;
		if (c_addr > ite->first && c_addr < ite->second) {
			return true;
		}
	}
	return false;
}


void Target2Addr(map<uint64_t, uint64_t> gt_ref, set<uint64_t> fn_functions){
	map<uint64_t, uint64_t> result;
	for(std::map<uint64_t, uint64_t>::iterator ite=gt_ref.begin(); ite!=gt_ref.end();++ite) {
		if (fn_functions.count(ite->second)) {
			result[ite->first] = ite->second;
			cout << "Found Target " << hex << ite->first << " " << ite->second << endl;
		}
	}
}

// compare the difference between two set, if flag is true return overlap function, else return difference
set<uint64_t> compareFunc(set<uint64_t> eh_functions, set<uint64_t> gt_functions, bool flag){
	set<uint64_t> res;
	for (auto func:gt_functions){
		if (flag) {
			if (eh_functions.count(func) && func!=0){
				res.insert(func);
			}
		} else{
			if (!eh_functions.count(func) && func!=0){
				res.insert(func);
			}
		}
	}
	return res;
}

void unionSet(set<Address> set1, set<Address> &set2){
	for (auto item : set1) {
		if (!set2.count(item)){
			set2.insert(item);
		}
	}
}


void ScanAddrInGap(map<uint64_t, uint64_t> gap_regions, set<Address> dataRef, set<Address> &RefinGap){
	// serach for result in gap regions
	for (auto ref : dataRef){
		for(std::map<uint64_t, uint64_t>::iterator ite=gap_regions.begin(); ite!=gap_regions.end();++ite) {
			uint64_t c_addr = (uint64_t) ref;
			if (c_addr >= ite->first && c_addr < ite->second) {
				RefinGap.insert(c_addr);
#ifdef DEBUG
				cout << "ref in gap: " << hex << c_addr << " in gap: " << ite->first << " -> "
					<< ite->second << endl;
#endif
				break;
			}
		}
	}
}

class nopVisitor : public InstructionAPI::Visitor{
	public:
		nopVisitor() : foundReg(false), foundImm(false), foundBin(false), isNop(true) {}
		virtual ~nopVisitor() {}

		bool foundReg;
		bool foundImm;
		bool foundBin;
		bool isNop;

		virtual void visit(BinaryFunction*) {
			if (foundBin) isNop = false;
			if (!foundImm) isNop = false;
			if (!foundReg) isNop = false;
			foundBin = true;
		}

		virtual void visit(Immediate *imm) {
			if (imm != 0) isNop = false;
			foundImm = true;
		}

		virtual void visit(RegisterAST *) {
			foundReg = true;
		}

		virtual void visit(Dereference *){
			isNop = false;
		}
};

bool isNopInsn(Instruction insn) {
	if(insn.getOperation().getID() == e_nop){
		return true;
	}
	/* too aggressive. comment it out
	if(insn.getOperation().getID() == e_lea){
		set<Expression::Ptr> memReadAddr;
		insn.getMemoryReadOperands(memReadAddr);
		set<RegisterAST::Ptr> writtenRegs;
		insn.getWriteSet(writtenRegs);

		if(memReadAddr.size() == 1 && writtenRegs.size() == 1) {
			if (**(memReadAddr.begin()) == **(writtenRegs.begin())) {
				return true;
			}
		}
		nopVisitor visitor;

		insn.getOperand(1).getValue()->apply(&visitor);
		if (visitor.isNop) {
			return true;
		}
	}*/
	return false;
}


void ScanGaps(map<uint64_t, uint64_t> gap_regions, map<uint64_t, uint64_t> scanTarget){
	set<Address> gap_set;
	// serach for result in gap regions
	for (auto item : scanTarget){
		bool found = false;
		for(std::map<uint64_t, uint64_t>::iterator ite=gap_regions.begin(); ite!=gap_regions.end();++ite) {
			if (item.first >= ite->first && item.first <= ite->second) {
				//gap_set.insert(a_addr);
				found = true;
				break;
			}
		}
		if (!found) {
			cout << "Ref: " << hex << item.first << " Target: " << item.second << endl;
		}
	}
}


map<uint64_t, uint64_t> getGaps(map<uint64_t, uint64_t> functions, vector<SymtabAPI::Region *> regs, uint64_t &gap_regions_num){
	std::map<uint64_t, uint64_t> gap_regions;
	std::map<uint64_t, uint64_t>::iterator it=functions.begin();
	unsigned long last_end;
	for (auto &reg: regs){
		uint64_t addr = (uint64_t) reg->getMemOffset();
		uint64_t addr_end = addr + (uint64_t) reg->getMemSize();
		uint64_t start = (uint64_t) it->first;
		if (addr_end <= start) {
			continue;
		}
		if (start > addr) {
			gap_regions[addr] = start;
			++gap_regions_num;
		}
		while (it != functions.end()){
       			uint64_t block_end = (uint64_t) it->second;
       			++it;
			uint64_t block_start = (uint64_t) it->first;
			if (block_end > addr_end){
				std::cout << "Error: Check Region" << std::endl;
				cout << hex << block_end << " " << addr_end << endl;
				exit(1);
			}
			if (block_start < addr_end){
				if (block_start > block_end){
					gap_regions[block_end] = block_start;
					++gap_regions_num;
				}
			}else{
				if (addr_end > block_end){
					gap_regions[block_end] = addr_end;
					++gap_regions_num;
				}
				break;
			}
		}
		last_end = addr_end;
		if (it == functions.end()) {
			break;
		}
	}
	if (it != functions.end() && last_end > it->second){
		gap_regions[it->second] = last_end;
		++gap_regions_num;
	}
	return gap_regions;
}

