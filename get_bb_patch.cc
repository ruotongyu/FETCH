/*
 * Dyinst Get basic block and function information.
 * 
 * Reference: https://github.com/dyninst/dyninst/blob/master/parseAPI/doc/example.cc
 * cfg's basic block terminator includes `call`.
 *
 * g++ -o get_bb_patch get_bb_patch.cc blocks.pb.cc -lboost_system -ldyninstAPI -lparseAPI -linstructionAPI `pkg-config --cflags --libs protobuf`
 */

#include <stdio.h>
#include <map>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include "blocks.pb.h"
#include "CFG.h"
#include "BPatch.h"
#include "BPatch_function.h"
#include "BPatch_Vector.h"
#include "BPatch_flowGraph.h"
#include "BPatch_basicBlock.h"

using namespace Dyninst;
using namespace std;
#define DEBUG

int main(int argc, char * argv[])
{
   map<uint64_t, bool> seen;
   
   if (argc < 3){
     cerr << "[ERROR]: please specify the binary path and output path" << endl;
     exit(-1);
   }
    
   std::string filePath = std::string(argv[1]);
   fstream output(argv[2], ios::out | ios::trunc | ios::binary);
   blocks::module pbModule;

   BPatch bpatch;
   BPatch_binaryEdit *binedit = bpatch.openBinary(argv[1]);
   BPatch_image *appImage = binedit->getImage();
   std::vector<BPatch_function *> *funcList;
   funcList = appImage->getProcedures();

   // Create a new binary code object from the filename argument
   //sts = new SymtabCodeSource(argv[1]);
   //co = new CodeObject(sts);
   
   // Parse the binary
   //co->parse();
   
   // Print the control flow graph
   auto fit = funcList->begin();
   for (int i = 0; fit != funcList->end(); ++fit, i++) { // i is index for clusters
      blocks::Function* pbFunc = pbModule.add_fuc();
      BPatch_function *f = *fit;
      
      // debug, print function name and its address
#ifdef DEBUG
     cout << "function name is " << f->getName()
	  << " its address is " << hex << f->getBaseAddr()
	  << " its type is " << Dyninst::ParseAPI::convert(f)->src()
	  << endl;
#endif
     pbFunc->set_va((uint64_t)f->getBaseAddr());

     // function return status
     // if (f->retstatus() == NORETURN)
     BPatch_flowGraph *fg = f->getCFG();

     std::set<BPatch_basicBlock *> blocks;
     fg->getAllBasicBlocks(blocks);
     auto bit = blocks.begin();
      for ( ; bit != blocks.end(); ++bit) {
         BPatch_basicBlock *b = *bit;
         // Don't revisit blocks in shared code
         if(seen.find(b->getStartAddress()) != seen.end())
            continue;

	 blocks::BasicBlock* pbBB = pbFunc->add_bb();
	 pbBB->set_va(b->getStartAddress());
	 pbBB->set_parent((uint64_t)f->getBaseAddr());
         
         seen[b->getStartAddress()] = true;
         
#ifdef DEBUG
	 cout << "basic block address is "
	      << hex << b->getStartAddress() 
	      << " size is " << b->getEndAddress() - b->getStartAddress()
	      << endl;
#endif
         
	 std::vector<BPatch_basicBlock*> targets;
	 b->getTargets(targets);
         auto it = targets.begin();
         for ( ; it != targets.end(); ++it) {
            if(!*it) continue;
	    auto suc = *it;
	    // edge type: CALL = 0; COND_TAKEN; COND_NOT_TAKEN
	    // INDIRECT; DIRECT; FALLTHROUGH; CATCH;
	    // CALL_FT; RET; NOEDGE; _edgetype_end_

	    blocks::Child* pbSuc = pbBB->add_child();
	    pbSuc->set_va(suc->getStartAddress());
#ifdef DEBUG
	    cout << "edge: "
	         << hex << b->getStartAddress()
		 << " -> "
		 << hex << suc->getStartAddress() << endl;
#endif
         }
	 // decode the basic block's instructions
	 std::vector<InstructionAPI::Instruction> insns;
	 b->getInstructions(insns);
	 auto inst_iter = insns.begin();
	 unsigned inst_addr = (unsigned)b->getStartAddress(); 
	 for (inst_iter = insns.begin(); inst_iter != insns.end(); ++inst_iter){
	   InstructionAPI::Instruction insn = *inst_iter;
#ifdef DEBUG
	   cout << "instruction address is " << hex << inst_addr 
	        << " size is " << hex << insn.size() << endl;
#endif
	   blocks::Instruction* pbInst = pbBB->add_instructions();
	   pbInst->set_va(inst_addr);
	   pbInst->set_size(insn.size());
	   inst_addr += insn.size();
	 }

   }
   }
   // save the protobuf file
   if (!pbModule.SerializeToOstream(&output)) {
	 cerr << "Failed to write address book." << endl;
	 return -1;
   }
}
