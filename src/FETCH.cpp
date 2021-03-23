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
#include "protobuf/blocks.pb.h"
#include <sys/stat.h>
#include <iostream>
#include <capstone/capstone.h>
#include <Dereference.h>
#include <InstructionAST.h>
#include <Result.h>
#include "protobuf/blocks.pb.h"
#include "utils.h"
#include "loadInfo.h"
#include "Reference.h"

// header of stackheight parser
#include "stackheight/ehframe/EhframeParser.h"

// header of tail call detection
#include "tailcall/tailcall.h"


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
//#define DEBUG_DISASSEMBLE
bool Inst_help(Dyninst::ParseAPI::CodeObject &codeobj, set<unsigned>& all_instructions, map<unsigned long, unsigned long>& gap_regions, set<uint64_t> &invalid_inst){
	set<Address> seen;
	for (auto func: codeobj.funcs()){
		if(seen.count( func->addr())){
			continue;
		}
		seen.insert(func->addr());
		for (auto block: func->blocks()){
			Dyninst::ParseAPI::Block::Insns instructions;
			block->getInsns(instructions);
			unsigned cur_addr = block->start();
			//Check control flow graph
			for (auto succ: block->targets()){
				unsigned succ_addr = succ->trg()->start();

				if (!all_instructions.count(succ_addr)){
					if (succ_addr != 0xffffffff && !isInGaps(gap_regions, succ_addr)){
						return false;
					}
				}

			}
			if (InvalidBB(block)){
#ifdef DEBUG_DISASSEMBLE
				cout << "Invalid instruction " << hex << block->last() << endl;
#endif
				return false;
			}
			// go through all instructions
			for (auto it: instructions) {
				Dyninst::InstructionAPI::Instruction inst = it.second;

				if (invalid_inst.count(cur_addr)){
					return false;
				}
				if (!all_instructions.count(cur_addr)) {
					if (!isInGaps(gap_regions, cur_addr)){
						return false;
					}
				}
				cur_addr += inst.size();
			}
		}
	}
	return true;
}
std::set<uint64_t> CheckInst(set<Address>& addr_set, char* input_string, set<unsigned>& instructions, map<unsigned long, unsigned long>& gap_regions, set<uint64_t>& known_func, blocks::module &pbModule, set<uint64_t> &nops_inst, map<uint64_t, uint64_t> DataRef, map<uint64_t, uint64_t> CodeRef, set<uint64_t> &invalid_inst) {

	std::set<uint64_t> filted_funcs;

	//ParseAPI::SymtabCodeSource* symtab_cs = new SymtabCodeSource(input_string);
	ParseAPI::CodeObject* code_obj_gap = nullptr;
	ParseAPI::SymtabCodeSource* symtab_cs = nullptr;
	symtab_cs = new SymtabCodeSource(input_string);
	for (auto addr: addr_set){
		//auto code_obj_gap = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
		//code_obj_gap = new ParseAPI::CodeObject(symtab_cs, NULL, NULL, false, false);
		//code_obj_gap = new ParseAPI::CodeObject(symtab_cs);
		code_obj_gap = new ParseAPI::CodeObject(symtab_cs, NULL, NULL, false, true);
		CHECK(code_obj_gap) << "Error: Fail to create ParseAPI::CodeObject";

		code_obj_gap->parse(addr, true);
		code_obj_gap->finalize();
		if (Inst_help(*code_obj_gap, instructions, gap_regions, invalid_inst)){
#ifdef DEBUG_DISASSEMBLE
			cout << "Disassembly Address is 0x" << hex << addr << endl;
			cout << "Reference Address <<< Code: 0x" << hex << CodeRef[addr] << " <<< Data: 0x" << DataRef[addr] << endl;  
			DebugDisassemble(*code_obj_gap);
#endif
			ParseAPI::Function* entry_f = nullptr; 

			for(auto cur_f : code_obj_gap->funcs()){
				if (addr == cur_f->addr()){
					entry_f = cur_f;
					break;
				}
			}

			if (!entry_f || !CallingConvensionCheck(entry_f)){
				continue;
			}

			for (auto r_f : code_obj_gap->funcs()){
				uint64_t func_addr = (uint64_t) r_f->addr();

				if (known_func.count(func_addr) || nops_inst.count(func_addr)){
					continue;
				}

				int inst_num = 0;
				bool NopFunc = false;
				for (auto block: r_f->blocks()){
					Dyninst::ParseAPI::Block::Insns instructions;
					block->getInsns(instructions);
					for (auto p: instructions){
						auto inst = p.second;
						if (inst_num == 0 && isNopInsn(inst)){
							NopFunc = true;
						}
						inst_num += 1;
					}
				}

				if (inst_num > 0 && !NopFunc) {
					filted_funcs.insert(addr);
				}
			}
		}
		delete code_obj_gap;
	}
	delete symtab_cs;
	return filted_funcs;
}

void expandFunction(Dyninst::ParseAPI::CodeObject &codeobj, map<uint64_t, uint64_t>& pc_funcs, set<uint64_t> &eh_functions) {
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
			//uint64_t end_addr;
			//for (auto block: func->blocks()){
			//	Dyninst::ParseAPI::Block::Insns instructions;
			//	block->getInsns(instructions);
			//	end_addr = block->end();
			//}
			//pc_funcs[(uint64_t) func->addr()] = end_addr;
		}
	}
}

// for debug
void dumpStackHeight(ParseAPI::CodeObject* code_obj, const char* file_name){
    FrameParser fp(file_name);
    std::set<Dyninst::Address> seen;
    signed height;
    signed height_ret;

    for (auto func: code_obj->funcs()){

	if (seen.count(func->addr()))
	    continue;

	seen.insert(func->addr());

	for (auto block: func->blocks()){
	    ParseAPI::Block::Insns instructions;
	    block->getInsns(instructions);
	    for(auto inst: instructions){
		height_ret = fp.request_stack_height(inst.first, height);
		if (height_ret == HEIGHT_ERROR_CANT_FIND){
		    cerr << "Can't find the address " << hex << inst.first << " in ehframe" << endl;
		} else if (height_ret == HEIGHT_ERROR_NOT_BASED_ON_SP){
		    cerr << "CFA is not based on SP registers at " << hex << inst.first << "'s parent function " << func->addr()  << endl;
		} else if (height_ret){
		    cerr << "unknown error occurs when dumping stack height at " << inst.first << endl;
		} else {
		    cout << "Height at " << hex << inst.first << " is " << dec << height << endl; 
		}
	    }
	}
    }
}

set<uint64_t> getInsts(Dyninst::ParseAPI::CodeObject &codeobj, set<unsigned> &all_instructions, map<uint64_t, uint64_t> &bb_map, set<uint64_t> &nops_inst, set<uint64_t> &invalid_inst){
	std::set<Dyninst::Address> seen;
	set<uint64_t> block_list;
	for (auto func:codeobj.funcs()){
		if(seen.count(func->addr())){
			continue;
		}

		seen.insert(func->addr());

		//cout << "Function Start: " << hex << func->addr() << endl;
		for (auto block: func->blocks()){

			block_list.insert((uint64_t) block->start());
			bb_map[(uint64_t) block->start()] = (uint64_t) block->end();
			Dyninst::ParseAPI::Block::Insns instructions;
			block->getInsns(instructions);
			unsigned cur_addr = block->start();
			//cout << "Block Addr: " << hex << cur_addr << endl;
			for (auto p : instructions){
				Dyninst::InstructionAPI::Instruction inst = p.second;

				all_instructions.insert(cur_addr);
				//cout << "Inst: 0x" << hex << cur_addr << "  " << inst.format() << endl;
				for (int i = 1; i < inst.size(); i++){
					invalid_inst.insert(cur_addr + i);
				}

				cur_addr += inst.size();

				if (isNopInsn(inst)) {
					nops_inst.insert(cur_addr);
				}

				//cout << "Instruction Addr " << hex << cur_addr  << endl;
			}
		}
	}
	return block_list;
}

void dumpBlocks(blocks::Function* pbFunc, ParseAPI::Function* func, std::set<uint64_t>& visited_blocks){
	for (auto block: func->blocks()){
		if (visited_blocks.find(block->start()) != visited_blocks.end())
			continue;
		visited_blocks.insert(block->start());

		blocks::BasicBlock* pbBB = pbFunc->add_bb();
		pbBB->set_va(block->start());
		pbBB->set_parent(func->addr());
		Dyninst::ParseAPI::Block::Insns instructions;
		block->getInsns(instructions);
		unsigned cur_addr = block->start();
	//	cout << "Block Addr: " << hex << cur_addr << endl;
		for (auto p : instructions){
			Dyninst::InstructionAPI::Instruction inst = p.second;
			blocks::Instruction* pbInst = pbBB->add_instructions();
			pbInst->set_va(cur_addr);
			pbInst->set_size(inst.size());

			cur_addr += inst.size();
	//		cout << "Instruction Addr " << hex << cur_addr  << endl;
		}
		for (auto succ: block->targets()){
			blocks::Child* pbSuc = pbBB->add_child();
			pbSuc->set_va(succ->trg()->start());
	//		cout << "successor: " << hex << succ->trg()->start() << endl;
		}
		}
}

void dumpCFG(Dyninst::ParseAPI::CodeObject &codeobj, blocks::module &pbModule, const std::map<uint64_t, uint64_t>& merged_funcs){

	std::set<Dyninst::Address> seen;
	std::set<uint64_t> visited_blocks;
	Dyninst::Address cur_addr;

	std::map<uint64_t, std::set<uint64_t>> merged_map;
	std::map<uint64_t, ParseAPI::Function*> funcs_map;

	for(auto func: codeobj.funcs()){
		funcs_map[func->addr()] = func;
	}

	for(auto merge_func: merged_funcs){
		if(merged_map.find(merge_func.second) == merged_map.end()){
			merged_map[merge_func.second] = std::set<uint64_t>();
		} 
		merged_map[merge_func.second].insert(merge_func.first);
	}

	for (auto func:codeobj.funcs()){

		cur_addr = func->addr();
		if(seen.count(cur_addr)){
			continue;
		}

		// this is deleted functions
		if (merged_funcs.find(cur_addr) != merged_funcs.end()){
			continue;
		}

		seen.insert(cur_addr);

		blocks::Function* pbFunc = pbModule.add_fuc();
		pbFunc->set_va(cur_addr);
		dumpBlocks(pbFunc, func, visited_blocks);

		auto cur_func_iter = merged_map.find(cur_addr);

		// merge functions
		if (cur_func_iter != merged_map.end()){
			for(auto sub_funcs: cur_func_iter->second){
				auto cur_merge_iter = funcs_map.find(sub_funcs);
				if(cur_merge_iter != funcs_map.end()){
					dumpBlocks(pbFunc, cur_merge_iter->second, visited_blocks);
				}
			}
		}
	}
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
set<Address> getOperand(Dyninst::ParseAPI::CodeObject &codeobj, map<uint64_t, uint64_t> &ref_addr) {
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
						ref_addr[(uint64_t) addr] = (uint64_t) cur_addr;
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
								ref_addr[(uint64_t) ref_value] = (uint64_t) cur_addr;
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
										ref_addr[(uint64_t) ref_value] = (uint64_t) cur_addr;
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
							ref_addr[(uint64_t) ref_value] = (uint64_t) cur_addr;
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


set<Address> getDataRef(std::vector<SymtabAPI::Region *>& regs, uint64_t offset, char* input, char* x64, map<uint64_t, uint64_t> &RefMap){
	size_t code_size;
	struct stat results;
	char *buffer;
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

	buffer = new char[code_size + 1];
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
			if (x64 == "x86"){
				unsigned int* res = (unsigned int*)(buffer + addr_start + i);
				addr = (Address) *res;
			}else {
				Address* res = (Address*)(buffer + addr_start + i);
				addr = *res;
			}
			//cout << hex << *res << "  "<<endl;
			DataRef_res.insert(addr);
			RefMap[(uint64_t) addr] = (uint64_t) (i + m_offset);
		}
	}

	delete buffer;
	return DataRef_res;
}


int main(int argc, char** argv){
	std::set<uint64_t> eh_functions;
	map<uint64_t, uint64_t> pc_funcs;
	char* input_string = argv[1];
	char* output_string = argv[3];
	//char* input_block = argv[3];
	char* x64 = argv[2];

	getEhFrameAddrs(eh_functions, input_string, pc_funcs);
	auto symtab_cs = std::make_shared<ParseAPI::SymtabCodeSource>(input_string);

	auto code_obj_eh = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get(), nullptr , nullptr , false, true);
	//auto code_obj_eh = std::make_shared<ParseAPI::CodeObject>(symtab_cs.get());
	
	//set<uint64_t> raw_fn_functions = compareFunc(eh_functions, gt_functions, false);
	CHECK(code_obj_eh) << "Error: Fail to create ParseAPI::CodeObject";

	code_obj_eh->add_hints(eh_functions);
	code_obj_eh->parse();
	uint64_t file_offset = symtab_cs->loadAddress();

	expandFunction(*code_obj_eh, pc_funcs, eh_functions);
#ifdef DEBUG_EHFUNC	
	printMap(pc_funcs);
	exit(1);
#endif
	//get instructions and functions disassemled from eh_frame
	set<unsigned> instructions;
	set<uint64_t> bb_list;
	map<uint64_t, uint64_t> bb_map;
	set<uint64_t> nops_inst;
	blocks::module pbModule;
	set<uint64_t> invalid_inst;
	bb_list=getInsts(*code_obj_eh, instructions, bb_map, nops_inst, invalid_inst);

	//dumpStackHeight(code_obj_eh.get(), input_string);

#ifdef DEBUG_BASICBLOCK	
	printMap(bb_map);
	exit(1);
#endif
	std::vector<SymtabAPI::Region *> regs;
	std::vector<SymtabAPI::Region *> data_regs;
	symtab_cs->getSymtabObject()->getCodeRegions(regs);
	symtab_cs->getSymtabObject()->getDataRegions(data_regs);
	
	//initialize gap regions
	map<uint64_t, uint64_t> ref_addr;
	set<Address> codeRef;
	codeRef = getOperand(*code_obj_eh, ref_addr);
	map<uint64_t, uint64_t> gap_regions;
	uint64_t gap_regions_num = 0;
	gap_regions = getGaps(pc_funcs, regs, gap_regions_num);

#ifdef DEBUG_GAPS
	unsigned gap_size = 0;
	for (auto g_it = gap_regions.begin(); g_it != gap_regions.end(); g_it++){
		gap_size = g_it->second - g_it->first;
		if (gap_size < 0x10)
			continue;
		cout << "gap: " << hex << g_it->first << " -> " << g_it->second 
			<< " . Size " << gap_size << endl;
	}
#endif
	//ScanGaps(gap_regions, tailCall);
	//exit(1);
	//initialize data reference
	set<Address> dataRef;
	map<uint64_t, uint64_t> DataRefMap;
	dataRef = getDataRef(data_regs, file_offset, input_string, x64, DataRefMap);
	
	//merge code ref and data ref
	unionSet(codeRef, dataRef);

	// search data reference in gaps
	set<Address> RefinGap;
	ScanAddrInGap(gap_regions, dataRef, RefinGap);
	// indentified functions is all the function start which generated from recursively disassemble 	   the functions found in gaps
	//set<uint64_t> nops;
	
	auto new_funcs = CheckInst(RefinGap, input_string, instructions, gap_regions, eh_functions, pbModule, nops_inst, DataRefMap, ref_addr, invalid_inst);	

	for (auto cur_addr : new_funcs){
		code_obj_eh->parse(cur_addr, true);
	}

	auto ref_2c = CCReference(*code_obj_eh, regs, instructions);
	auto ref_d2c = DCReference(data_regs, regs, file_offset, input_string, x64, instructions);
	ref_2c.insert(ref_d2c.begin(), ref_d2c.end());

	// tail call detection
	std::map<uint64_t, uint64_t> merged_funcs;
	tailCallAnalyzer* tailcall_ana = new tailCallAnalyzer(code_obj_eh.get(), &ref_2c, &pc_funcs, input_string);
	// false means do not use ehframe to get stack height
	tailcall_ana->analyze(merged_funcs, true);

	dumpCFG(*code_obj_eh, pbModule, merged_funcs);
	auto output_file = const_cast<char* >(output_string);
	std::fstream output(output_file, std::ios::out | std::ios::trunc | std::ios::binary);
	if (!pbModule.SerializeToOstream(&output)){
		cout << "Failed to write the protocol buffer" << endl;
		return -1;
	}
	output.close();

	delete tailcall_ana;
	return 0;

}
