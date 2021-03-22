#include "tailcall.h"
#include "CFG.h"
#include "Symtab.h"
#include "CodeSource.h"
#include <vector>

#define DEBUG_TAIL_CALL

extern bool CallingConvensionCheck(ParseAPI::Function*);

tailCallAnalyzer::tailCallAnalyzer(ParseAPI::CodeObject* _co, std::map<uint64_t, uint64_t>* _refs, std::map<uint64_t, uint64_t>* _funcs_range, const char* _f_path){
    codeobj = _co;
    refs = _refs;
    funcs_range = _funcs_range;
    cached_func = 0;
    cached_sa = 0;
    frame_parser = new FrameParser(_f_path);
    f_path = _f_path;
}

tailCallAnalyzer::~tailCallAnalyzer(){
    delete frame_parser;

    if (cached_sa)
	delete cached_sa;
}

void tailCallAnalyzer::analyze(std::map<uint64_t, uint64_t>& merged_funcs, bool use_ehframe){
    std::set<uint64_t> targets;
    std::set<uint64_t> call_targets;
    std::map<uint64_t, ParseAPI::Function*> all_funcs;

    std::set<uint64_t> new_funcs;
    std::set<uint64_t> deleted_funcs;
    std::set<uint64_t> indirect_jump_targets;

    ParseAPI::CodeObject* code_obj_tmp = nullptr;
    ParseAPI::SymtabCodeSource* symtab_cs_tmp = nullptr;
    ParseAPI::Function* entry_f = nullptr;
    
    uint64_t cur_func_addr;
    int64_t cur_func_end;

    int32_t height;
    uint64_t target;


    // find the target of call instructions
    for(auto func: codeobj->funcs()){

	all_funcs[func->addr()] = func;

	for (auto bb: func->blocks()){
	    for(auto succ: bb->targets()){
		if (succ->type() == ParseAPI::CALL){
		    targets.insert(succ->trg()->start());
		    call_targets.insert(succ->trg()->start());
		} else if(succ->type() == ParseAPI::INDIRECT){
		    // collect all indirect jump targets
		    indirect_jump_targets.insert(succ->trg()->start());
		}
	    }
	}
    }

    for (auto ref: *refs){

	if (indirect_jump_targets.find(ref.second) != indirect_jump_targets.end())
	    continue;

	targets.insert(ref.second);
    }

    // iterate all jump edges
    for(auto func: codeobj->funcs()){

	cur_func_addr = func->addr();
	
	auto tmp_func_iter = funcs_range->find(cur_func_addr);

	if(tmp_func_iter != funcs_range->end()){
	    cur_func_end = tmp_func_iter->second;
	}else{
	    cur_func_end = -1;
	}

	for(auto bb: func->blocks()){
	    for(auto succ: bb->targets()){

		if (succ->trg()->start() == 0xffffffffffffffff)
		    continue;

		target = succ->trg()->start();

		// if target in the range of current function
		// skip
		if (cur_func_end != -1 && 
			target >= cur_func_addr && target < cur_func_end){
		    continue;
		}

		switch(succ->type()){
		    // bin: do not consider indirect jump for now.
		    case ParseAPI::COND_TAKEN:
		    case ParseAPI::DIRECT:
		    case ParseAPI::INDIRECT:
			if (getStackHeight(bb->lastInsnAddr(), func, bb, height, use_ehframe)){

#ifdef DEBUG_TAIL_CALL
			    std::cerr << "[Tail call detection]: The height in " << std::hex << bb->lastInsnAddr() << " : " << height << std::endl;
#endif
			    bool condition1 = false;
			    // check if the height of stack is balanced
			    if ((height == 8 || height == 4)){

				condition1 = true;
				// the target is already a function.
				// skip.

				if (all_funcs.find(target) != all_funcs.end()){
				    continue;
				}

				// there are other references to the target
				if(targets.find(target) != targets.end()){
#ifdef DEBUG_TAIL_CALL
					std::cerr << "[Tail call detection]: at " << std::hex << succ->src()->start() << 
					    ", the target " << succ->trg()->start() << " is a function!" << std::endl;
#endif
					new_funcs.insert(target);
				} 
				
			    } 

			    if (all_funcs.find(target) != all_funcs.end() && call_targets.find(target) == call_targets.end()){
				// detect non-continues 'function' caused by the entry in ehframe
				// firstly, the stack height is not equal to 0 or
				// secondly, there is no referecnes to the target except for current jump
				if(!condition1 || targets.find(target) == targets.end()){
#ifdef DEBUG_TAIL_CALL
				    std::cerr << "[Tail call detection]: merge function at " << std::hex << succ->trg()->start() << 
					" to function " << func->addr() << "!" << std::endl;
#endif
				    merged_funcs[target] = func->addr();
				    deleted_funcs.insert(target);
				}
			    }
			} // end if(getStackHeight...)
			else{
#ifdef DEBUG_TAIL_CALL
			    std::cerr << "[Tail call detection]: at file " << f_path << " Can't get height of address " << std::hex << bb->lastInsnAddr() << " to " << target << std::endl;
#endif
			}
			break;
		}
	    }
	}
    }

    for (auto func_addr: new_funcs){

	entry_f = nullptr;
	symtab_cs_tmp = new ParseAPI::SymtabCodeSource(const_cast<char*>(f_path));
	code_obj_tmp = new ParseAPI::CodeObject(symtab_cs_tmp, NULL, NULL, false, true);

	code_obj_tmp->parse(func_addr, true);
	code_obj_tmp->finalize();

	for (auto cur_f: code_obj_tmp->funcs()){
	    if (func_addr == cur_f->addr()){
		entry_f = cur_f;
		break;
	    }
	}

	// calling convension checking
	if (!entry_f || !CallingConvensionCheck(entry_f)){
	    delete code_obj_tmp;
	    delete symtab_cs_tmp;
	    continue;
	}
	
#ifdef DEBUG_TAIL_CALL
	std::cerr << "[Tail call detection]: create a new function at " 
	    << std::hex << func_addr << std::endl;
#endif

	codeobj->parse(func_addr, false);

	delete code_obj_tmp;
	delete symtab_cs_tmp;
    }

    // TODO. find a better way to merge these functions
    /*
    for (auto func_addr: deleted_funcs){

	auto cur_func_iter = all_funcs.find(func_addr);
	if (cur_func_iter == all_funcs.end())
		continue;

#ifdef DEBUT_TAIL_CALL
	std::cerr << "[Tail call detection]: delete function at "
	    << std::hex << func_addr << endl;
#endif
	std::cout << "destroy " << std::hex << func_addr << std::endl;

	// TODO.  merge the function
	//codeobj->destroy(cur_func_iter->second);
	//delete cur_func_iter->second;
    }
    */

}

bool tailCallAnalyzer::getStackHeight(uint64_t address, ParseAPI::Function* func, ParseAPI::Block* block, int32_t& height, bool use_ehframe){
    bool ret_result = false;
    std::stringstream ss;
    std::vector<std::pair<Absloc, StackAnalysis::Height>> heights;

    if (use_ehframe){
	    // request stack height from ehframe first
	    if (!frame_parser->request_stack_height(address, height)){
		return true;
	    }
    }


    // othersize, get stackheight from stack analysis of dyninst
    if (cached_func != func->addr()){

	if(cached_sa)
	    delete cached_sa;

	cached_sa = new StackAnalysis(func);
	cached_func = func->addr();
    }

    cached_sa->findDefinedHeights(block, address, heights);
    for (auto iter = heights.begin(); iter != heights.end(); iter++){
	const Absloc &loc = iter->first;
	if (!loc.isSP()){
	    continue;
	}

	StackAnalysis::Height &s_height = iter->second;
	if (s_height.isTop() || s_height.isBottom()){
	    continue;
	}
	ss << s_height;
	ss >> height;
	height = height * -1;
	ret_result = true;
	ss.clear();
	break;
    }

    return ret_result;
}
