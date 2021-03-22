/*
 * Dyinst Get basic block and function information.
 * 
 * Reference: https://github.com/dyninst/dyninst/blob/master/parseAPI/doc/example.cc
 * cfg's basic block terminator includes `call`.
 *
 * g++ -o get_bb get_bb.cc blocks.pb.cc -lboost_system -lparseAPI -linstructionAPI `pkg-config --cflags --libs protobuf`
 */

#include <stdio.h>
#include <map>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <fstream>
#include "CodeObject.h"
#include "blocks.pb.h"
#include "CFG.h"
#include "InstructionDecoder.h"

using namespace std;
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;

int main(int argc, char * argv[])
{
   map<Address, bool> seen;
   vector<Function *> funcs;
   SymtabCodeSource *sts;
   CodeObject *co;
   
   if (argc < 3){
     cerr << "[ERROR]: please specify the binary path and output path" << endl;
     exit(-1);
   }
    
   std::string filePath = std::string(argv[1]);
 // if (!OS::executableExists(filePath)) {
 //   cerr << "[ERROR]: can't get the input file path" << endl;
 //   exit(-1);
 // }
   fstream output(argv[2], ios::out | ios::trunc | ios::binary);
 //  fileDescriptor fileDes = fileDescriptor(argv[1], 0 /*code base address*/, 0 /*data base address*/);
 //  image* curImage = new image (fileDes, false, /*err*/
 //     				BPatch_NormalMode, /*BPatch_hybridMode*/
//			       parseGaps/* true*/)	

   blocks::module pbModule;

   // Create a new binary code object from the filename argument
   sts = new SymtabCodeSource(argv[1]);
   co = new CodeObject(sts);
   //co = curImage->codeObject();
   
   // Parse the binary
   co->parse();
   
   // Print the control flow graph
   const CodeObject::funclist& all = co->funcs();
   auto fit = all.begin();
   for (int i = 0; fit != all.end(); ++fit, i++) { // i is index for clusters
      blocks::Function* pbFunc = pbModule.add_fuc();
      Function *f = *fit;
      
      // debug, print function name and its address
     cout << "function name is " << f->name()
	  << " its address is " << hex << f->addr()
	  << endl;
     pbFunc->set_va(f->addr());

     // function return status
     // if (f->retstatus() == NORETURN)
      auto bit = f->blocks().begin();
      for ( ; bit != f->blocks().end(); ++bit) {
         Block *b = *bit;
         // Don't revisit blocks in shared code
         if(seen.find(b->start()) != seen.end())
            continue;

	 blocks::BasicBlock* pbBB = pbFunc->add_bb();
	 pbBB->set_va(b->start());
	 pbBB->set_parent(f->addr());
         
         seen[b->start()] = true;
         
	 cout << "basic block address is "
	      << hex << b->start() 
	      << " size is " << b->size()
	      << endl;
         
         auto it = b->targets().begin();
         for ( ; it != b->targets().end(); ++it) {
            if(!*it) continue;
	    string call = "";
	    // edge type: CALL = 0; COND_TAKEN; COND_NOT_TAKEN
	    // INDIRECT; DIRECT; FALLTHROUGH; CATCH;
	    // CALL_FT; RET; NOEDGE; _edgetype_end_
            if((*it)->type() == CALL_FT)
	      call = "[call]";

	    blocks::Child* pbSuc = pbBB->add_child();
	    pbSuc->set_va((*it)->trg()->start());

	    cout << "edge: "
	         << hex << (*it)->src()->start()
		 << " -> "
		 << hex << (*it)->trg()->start()
		 << call << endl;
         }
	 // decode the basic block's instructions
	 Offset off = b->start();
	 const unsigned char *ptr =
		       (const unsigned char *)b->region()->getPtrToInstruction(off);
         if (ptr != NULL){
	       InstructionDecoder d(ptr, b->size(), b->obj()->cs()->getArch());
	       while (off < b->end()) {
		       std::make_ptr<Instruction insn = d.decode();
		       unsigned address = b->start() + off;
		       off += insn.size();
		       cout << "instruction address is " << hex << address
			    << " size is " << hex << insn.size() << endl;
		       blocks::Instruction* pbInst = pbBB->add_instructions();
		       pbInst->set_va(address);
		       pbInst->set_size(insn.size());
       }
	 }
      }

   }
   // save the protobuf file
   if (!pbModule.SerializeToOstream(&output)) {
	 cerr << "Failed to write address book." << endl;
	 return -1;
   }
}
