#include <stdio.h>
#include <sstream>
#include <fstream>
#include <set>
#include <cstdint>
#include "CodeObject.h"
#include "Function.h"
#include "Symtab.h"
#include "Instruction.h"
#include "BinaryFunction.h"
#include "glog/logging.h"
#include "gflags/gflags.h"
#include "blocks.pb.h"
#include <sys/stat.h>
#include <iostream>
#include <capstone/capstone.h>
#include <Dereference.h>
#include <InstructionAST.h>
#include <Result.h>
#include "refInf.pb.h"
#include "blocks.pb.h"
#include "utils.h"
#include "loadInfo.h"

using namespace Dyninst;
using namespace SymtabAPI;
using namespace std;
using namespace InstructionAPI;
using namespace Dyninst::ParseAPI;

//#define DEBUG
//#define FN_PRINT
//#define FNGAP_PRINT
//#define DEBUG_GAPS
//#define DEBUG_BASICBLOCK
//#define FN_GAP_PRINT	
//#define DEBUG_EHFUNC
bool Inst_help(Dyninst::ParseAPI::CodeObject &codeobj, set<Address> &res, set<unsigned> all_instructions, map<unsigned long, unsigned long> gap_regions, set<unsigned> &dis_inst, set<uint64_t> &nops){
	set<Address> seen;
	for (auto func: codeobj.funcs()){
		if(seen.count( func->addr())){
			continue;
		}
		seen.insert(func->addr());
		res.insert(func->addr());
		for (auto block: func->blocks()){
			Dyninst::ParseAPI::Block::Insns instructions;
			block->getInsns(instructions);
			unsigned cur_addr = block->start();
			//Check control flow graph
			for (auto succ: block->targets()){
				unsigned succ_addr = succ->trg()->start();
				if (succ_addr == 4294967295){
					continue;
				}
				if (!all_instructions.count(succ_addr)){
					if (!isInGaps(gap_regions, succ_addr)){
						//cout << "Faill on Control flow Check" << endl;
						return false;
					}
				}
			}
			// go through all instructions
			for (auto it: instructions) {
				dis_inst.insert(cur_addr);
				Dyninst::InstructionAPI::Instruction inst = it.second;
				//Check inlegall instruction
				if (!inst.isLegalInsn() || !inst.isValid()){
					//cout << "Invalid Instruction: " << cur_addr << endl;
					return false;
				}
				//if (cur_addr >= 7086240 and cur_addr <= 7086340){
				//	cout << hex << cur_addr << " " << inst.format() << endl;
				//}
				//Check conflict instructions
				if (!all_instructions.count(cur_addr)) {
					if (!isInGaps(gap_regions, cur_addr)){
						return false;
					}
				}
				if (isNopInsn(inst)) {
					nops.insert(cur_addr);
				}
				cur_addr += inst.size();
			}
		}
	}
	return true;
}

void deleteObj(ParseAPI::CodeObject* obj){
	for (auto func: obj->funcs()){
		for (auto block: func->blocks()){
			delete block;
		}
		delete func;
	}
	delete obj;
}

set<uint64_t> CheckInst(set<Address> addr_set, char* input_string, set<unsigned> instructions, map<unsigned long, unsigned long> gap_regions, map<uint64_t, Address> &Add2Ref, set<uint64_t> &dis_addr, set<uint64_t> &nops) {
	set<uint64_t> identified_functions;
	//ParseAPI::SymtabCodeSource* symtab_cs = new SymtabCodeSource(input_string);
	ParseAPI::CodeObject* code_obj_gap = nullptr;
	ParseAPI::SymtabCodeSource* symtab_cs = nullptr;
	for (auto addr: addr_set){
		//auto code_obj_gap = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
		//cout << "Disassemble gap at " << hex << addr << endl;
		symtab_cs = new SymtabCodeSource(input_string);
		code_obj_gap = new ParseAPI::CodeObject(symtab_cs);
		CHECK(code_obj_gap) << "Error: Fail to create ParseAPI::CodeObject";
		code_obj_gap->parse(addr, true);
		set<Address> func_res;
		set<unsigned> dis_inst;
		//if (addr == 5448336) {
		//	DebugDisassemble(*code_obj_gap);
		//}

		if (Inst_help(*code_obj_gap, func_res, instructions, gap_regions, dis_inst, nops)){
			//cout << "Disassembly Address is 0x" << hex << addr << endl;
			dis_addr.insert((uint64_t) addr);
			for (auto r_f : func_res){
				Add2Ref[(uint64_t) r_f] = addr;
				identified_functions.insert((uint64_t) r_f);
				//cout << "Func  0x" <<std::hex << r_f << endl;
			}
		}
		
		//delete code_obj_gap;
		deleteObj(code_obj_gap);
		delete symtab_cs;
	}
	return identified_functions;
}

void expandFunction(Dyninst::ParseAPI::CodeObject &codeobj, map<uint64_t, uint64_t> &pc_funcs, set<uint64_t> &eh_functions) {
	std::set<Dyninst::Address> seen;
	for (auto func:codeobj.funcs()){
		if (seen.count(func->addr())){
			continue;
		}
		seen.insert(func->addr());
		bool found = false;
		for (map<uint64_t, uint64_t>::iterator it=pc_funcs.begin(); it != pc_funcs.end(); ++it){
			if (func->addr() >= it->first && func->addr() <= it->second){
				found = true;
				break;
			}
		}
		if (!found) {
			eh_functions.insert((uint64_t) func->addr());
			for (auto block: func->blocks()){
				pc_funcs[(uint64_t) block->start()] = (uint64_t) block->end();
			}
		}
	}
}

set<uint64_t> dumpCFG(Dyninst::ParseAPI::CodeObject &codeobj, set<unsigned> &all_instructions, map<uint64_t, uint64_t> &bb_map){
	std::set<Dyninst::Address> seen;
	set<uint64_t> block_list;
	for (auto func:codeobj.funcs()){
		if(seen.count(func->addr())){
			continue;
		}
		seen.insert(func->addr());
		for (auto block: func->blocks()){
			block_list.insert((uint64_t) block->start());
			bb_map[(uint64_t) block->start()] = (uint64_t) block->end();
			Dyninst::ParseAPI::Block::Insns instructions;
			block->getInsns(instructions);
			unsigned cur_addr = block->start();
			for (auto p : instructions){
				Dyninst::InstructionAPI::Instruction inst = p.second;
				all_instructions.insert(cur_addr);
				cur_addr += inst.size();
				//cout << "Instruction Addr " << hex << cur_addr  << endl;
			}
		}
	}
	return block_list;
}

bool isCFIns(InstructionAPI::Instruction* ins){
	switch (ins->getCategory()){
		case InstructionAPI::c_CallInsn:
		case InstructionAPI::c_BranchInsn:
		case c_ReturnInsn:
			return true;
			break;
		default:
			return false;
	}
}
set<Address> getOperand(Dyninst::ParseAPI::CodeObject &codeobj, map<Address, Address> &ref_addr) {
	set<Address> constant;
	Address ref_value;
	// pc pointer
	unsigned cur_addr = 0x0;
	unsigned next_addr = 0x0;
	for (auto func:codeobj.funcs()) {
		for (auto block: func->blocks()){
			Dyninst::ParseAPI::Block::Insns instructions;
			block->getInsns(instructions);

			// get current address
			for (auto it: instructions) {
				Dyninst::InstructionAPI::Instruction inst = it.second;
				InstructionAPI::RegisterAST thePC = InstructionAPI::RegisterAST::makePC(inst.getArch());

				cur_addr = it.first;
				next_addr = cur_addr + inst.size();
				std::vector<InstructionAPI::Operand> operands;
				inst.getOperands(operands);
				for (auto operand:operands){
					auto expr = operand.getValue();
					if (auto imm = dynamic_cast<InstructionAPI::Immediate *>(expr.get())) { // immediate operand
						Address addr = imm->eval().convert<Address>();
						constant.insert(addr);
						ref_addr[addr] = cur_addr;
#ifdef DEBUG
						cout << "[ref imm]: instruction at " << hex << cur_addr << " ref target is " << addr << endl;
#endif
					}
					else if (auto dref = dynamic_cast<InstructionAPI::Dereference *>(expr.get())){ // memeory operand
						std::vector<InstructionAPI::InstructionAST::Ptr> args;
						dref->getChildren(args);

						if (auto d_expr = dynamic_cast<InstructionAPI::Expression *>(args[0].get())){
							std::vector<InstructionAPI::Expression::Ptr> exps;

							// bind the pc value.
							d_expr->bind(&thePC, InstructionAPI::Result(InstructionAPI::u64, next_addr));
							ref_value = d_expr->eval().convert<Address>();
							constant.insert(ref_value);
							if (ref_value){
								ref_addr[ref_value] = cur_addr;
								constant.insert(ref_value);
#ifdef DEBUG
								cout << "[ref mem]: instruction at " << hex << cur_addr << " ref target is " << ref_value << endl;
#endif
								continue; // do not iterate over exprs
							}

							d_expr->getChildren(exps);
							for (auto dref_expr : exps){
								if (auto dref_imm = dynamic_cast<InstructionAPI::Immediate *>(dref_expr.get())){
										ref_value = dref_imm->eval().convert<Address>();
										constant.insert(ref_value);
										ref_addr[ref_value] = cur_addr;
										//cout << "instruction addr: " << std::hex << cur_addr << " mem operand is " << std::hex << ref_value << endl;
										}
							}

						}
					} else if (auto binary_func = dynamic_cast<InstructionAPI::BinaryFunction *>(expr.get())){ // binary operand. such as add,sub const(%rip)
						if (isCFIns(&inst))
							continue;

						binary_func->bind(&thePC, InstructionAPI::Result(InstructionAPI::u64, next_addr));
						ref_value = binary_func->eval().convert<Address>();
						if (ref_value){
							ref_addr[ref_value] = cur_addr;
							constant.insert(ref_value);
#ifdef DEBUG
							cout << "[ref bin]: instruction at " << hex << cur_addr << " ref target is " << ref_value << endl;
#endif
						}
					}
				}
			}
		}
	}
	return constant;
}


set<Address> getDataRef(std::vector<SymtabAPI::Region *> regs, uint64_t offset, char* input, char* x64, map<Address, unsigned long> &RefMap){
	size_t code_size;
	struct stat results;
	string list[6] = {".rodata", ".data", ".fini_array", ".init_array", ".data.rel.ro", ".data.rel.ro.local"};
	set<string> white_list;
	for (int i = 0; i < 6; ++i) {
		white_list.insert(list[i]);
	}

	if (stat(input, &results) == 0) {
		code_size = results.st_size;
	}
	set<Address> DataRef_res;
	std::ifstream handleFile (input, std::ios::in | ios::binary);
	char buffer[code_size];
	handleFile.read(buffer, code_size);
	for (auto &reg: regs){
		if (!white_list.count(reg->getRegionName())){
			continue;	
		}
		unsigned long addr_start = (unsigned long) reg->getFileOffset();
		unsigned long m_offset = (unsigned long) reg->getMemOffset();
		//unsigned long addr_start = start - (unsigned long) offset; 
		unsigned long region_size = (unsigned long) reg->getMemSize();
		//void * d_buffer = (void *) &buffer[addr_start];
		for (int i = 0; i < region_size; ++i) {
			if (i + addr_start > code_size) {
				break;
			}
			if ((i + m_offset)%4 != 0) {
				continue;
			}
			Address addr;
			if (x64 == "x32"){
				unsigned int* res = (unsigned int*)(buffer + addr_start + i);
				addr = (Address) *res;
			}else {
				Address* res = (Address*)(buffer + addr_start + i);
				addr = *res;
			}
			//cout << hex << *res << "  "<<endl;
			DataRef_res.insert(addr);
			RefMap[addr] = i + m_offset;
		}
	}
	return DataRef_res;
}


int main(int argc, char** argv){
	std::set<uint64_t> eh_functions;
	map<uint64_t, uint64_t> pc_funcs;
	char* input_string = argv[1];
	char* input_pb = argv[2];
	char* input_block = argv[3];
	char* x64 = argv[4];

	// The number of functions extract from eh_frame
	int RAW_EH_NUM = 0;
	// The number of functions from recursive disassemle from eh_frame
	int REU_EH_NUM = 0;
	// The number of ground truth functions
	int GT_NUM = 0;
	// load false negative functions with reference
	map<uint64_t, uint64_t> ref2Addr;
	loadFnAddrs(input_string, ref2Addr);
	getEhFrameAddrs(eh_functions, input_string, pc_funcs);
	auto symtab_cs = std::make_shared<ParseAPI::SymtabCodeSource>(input_string);
	auto code_obj_eh = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
	
	//get call instructions and functions from ground truth
	set<uint64_t> call_inst;
	set<uint64_t> gt_functions;
	blocks::module mModule;
	call_inst = loadGTFunc(input_block, mModule, gt_functions);
	set<uint64_t> raw_fn_functions = compareFunc(eh_functions, gt_functions, false);
	RAW_EH_NUM = raw_fn_functions.size();
	GT_NUM = gt_functions.size();
	CHECK(code_obj_eh) << "Error: Fail to create ParseAPI::CodeObject";
	code_obj_eh->parse();
	uint64_t file_offset = symtab_cs->loadAddress();
	for(auto addr : eh_functions){
		code_obj_eh->parse(addr, true);
	}
	
	//pc_sets include all function start after recursive disassembling from ehframe
	expandFunction(*code_obj_eh, pc_funcs, eh_functions);
#ifdef DEBUG_EHFUNC	
	printMap(pc_funcs);
	exit(1);
#endif
	//get instructions and functions disassemled from eh_frame
	set<unsigned> instructions;
	set<uint64_t> bb_list;
	map<uint64_t, uint64_t> bb_map;
	bb_list=dumpCFG(*code_obj_eh, instructions, bb_map);
#ifdef DEBUG_BASICBLOCK	
	printMap(bb_map);
	exit(1);
#endif
	set<uint64_t> fn_functions = compareFunc(eh_functions, gt_functions, false);
	REU_EH_NUM = fn_functions.size();
	PrintFuncResult(RAW_EH_NUM, REU_EH_NUM, GT_NUM);
	for (auto func: fn_functions){
		cout << hex << func <<endl;
	}
	exit(1);
	//CheckLinker()
	std::vector<SymtabAPI::Region *> regs;
	std::vector<SymtabAPI::Region *> data_regs;
	symtab_cs->getSymtabObject()->getCodeRegions(regs);
	symtab_cs->getSymtabObject()->getDataRegions(data_regs);
	
	//get plt section region
	uint64_t plt_start, plt_end;
	getPltRegion(plt_start, plt_end, regs);
	
	// read reference ground truth from pb file
	map<uint64_t, uint64_t> gt_ref;
	RefInf::RefList refs_list;
	gt_ref = loadGTRef(input_pb, refs_list);
	//get Tareget to Reference address
	//Target2Addr(gt_ref, fn_functions);
	//initialize gap regions
	map<Address, Address> ref_addr;
	set<Address> codeRef;
	codeRef = getOperand(*code_obj_eh, ref_addr);
	map<uint64_t, uint64_t> gap_regions;
	uint64_t gap_regions_num = 0;
	gap_regions = getGaps(bb_map, regs, gap_regions_num);
#ifdef DEBUG_GAPS
	unsigned gap_size = 0;
	for (auto g_it = gap_regions.begin(); g_it != gap_regions.end(); g_it++){
		gap_size = g_it->second - g_it->first;
		if (gap_size < 0x10)
			continue;
		cout << "gap: " << hex << g_it->first << " -> " << g_it->second 
			<< " . Size " << gap_size << endl;
	}
	exit(-1);
#endif
	//ScanGaps(gap_regions, tailCall);
	//exit(1);
	//initialize data reference
	set<Address> dataRef;
	map<Address, unsigned long> DataRefMap;
	dataRef = getDataRef(data_regs, file_offset, input_string, x64, DataRefMap);
	
	//merge code ref and data ref
	unionSet(codeRef, dataRef);

	// search data reference in gaps
	set<Address> RefinGap;
	ScanAddrInGap(gap_regions, dataRef, RefinGap);
	// indentified functions is all the function start which generated from recursively disassemble 	   the functions found in gaps
	set<uint64_t> identified;
	map<uint64_t, Address> Add2Ref;
	set<uint64_t> dis_addr;
	set<uint64_t> nops;
	identified = CheckInst(RefinGap, input_string, instructions, gap_regions, Add2Ref, dis_addr, nops);	
	set<uint64_t> fixed;
	set<uint64_t> undetect;
	set<uint64_t> FNTailCall;
	set<uint64_t> fnInGap;
	set<uint64_t> fnInCode;
	
	getFunctions(identified, fn_functions, undetect, fixed);
	
	functionInGaps(undetect, fnInGap, fnInCode, gap_regions);
	FNTailCall = printTailCall(fnInCode, eh_functions, bb_list);
	cout << "Function Solved: " << dec << fixed.size() << endl;
	//cout << dec << fn_functions.size() << " solved: " << fixed.size() << " un: " << undetect.size() << endl;
	cout << dec << "In Code: " << fnInCode.size() << ", In Gaps: " << fnInGap.size() << endl;
	map<uint64_t, uint64_t> withRef;
	PrintRefInGaps(fnInGap, gt_ref, withRef);
	identifiedWrong(identified, gt_functions, plt_start, plt_end, nops);
	cout << "#########################" << endl;
	cout << "#########################" << endl;
}
