/*
 * See the dyninst/COPYRIGHT file for copyright information.
 * 
 * We provide the Paradyn Tools (below described as "Paradyn")
 * on an AS IS basis, and do not warrant its validity or performance.
 * We reserve the right to update, modify, or discontinue this
 * software at any time.  We shall have no obligation to supply such
 * updates or modifications or any other form of support to you.
 * 
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

// $Id: liveness.C,v 1.12 2008/09/04 21:06:20 bill Exp $
//
#include "CFG.h"
#include "Location.h"
#include "InstructionDecoder.h"
#include "Register.h"
#include "Instruction.h"

#include "livenessAnaEhframe.h"
#include "ABI.h"
#include <boost/bind.hpp>

extern bool isNopInsn(Instruction insn);

#define DEBUG_LIVENESS 0
std::string regs1 = " ttttttttddddddddcccccccmxxxxxxxxxxxxxxxxgf                  rrrrrrrrrrrrrrrrr";
std::string regs2 = " rrrrrrrrrrrrrrrrrrrrrrrm1111110000000000ssoscgfedrnoditszapci11111100dsbsbdca";
std::string regs3 = " 7654321076543210765432105432109876543210bbrssssssftfffffffffp54321098iippxxxx";

using namespace std;
using namespace Dyninst;
using namespace Dyninst::ParseAPI;
using namespace Dyninst::InstructionAPI;
using namespace EHFrameAna;

#define liveness_cerr if(DEBUG_LIVENESS) cerr
#define liveness_printf(format, args...) do {if (DEBUG_LIVENESS) printf(format, ## args); } while(0)

// Code for register liveness detection
LivenessAnalyzer::LivenessAnalyzer(int w): errorno((ErrorType)-1) {
    width = w;
    abi = ABI::getABI(width);
}

int LivenessAnalyzer::getIndex(MachRegister machReg){
   return abi->getIndex(machReg);
}

const bitArray& LivenessAnalyzer::getLivenessIn(Block *block) {
    // Calculate if it hasn't been done already
    liveness_cerr << endl << "LivenessAnalyzer::getLivenessIn()" << endl;
    liveness_cerr << "Getting liveness for block " << hex << block->start() << dec << endl;
    assert(blockLiveInfo.find(block) != blockLiveInfo.end());
    livenessData& data = blockLiveInfo[block];
    assert(data.in.size());
    return data.in;
}

void LivenessAnalyzer::processEdgeLiveness(Edge* e, livenessData& data, Block* block,
					   const bitArray& allRegsDefined)
{
  // covered by Intraproc predicate
  //if ((*eit)->type() == CALL) continue;
  // Is this correct?
  if (e->type() == CATCH) return;
  if (e->sinkEdge()) {
    liveness_cerr << "Sink edge from " << hex << block->start() << dec << endl;
    data.out |= allRegsDefined;
    return;
  }
  
  // TODO: multiple entry functions and you?
  data.out |= getLivenessIn(e->trg());
  liveness_cerr << "Accumulating from block " << hex << (e->trg())->start() << dec << endl;
  liveness_cerr << data.out << endl;
}


const bitArray& LivenessAnalyzer::getLivenessOut(Block *block, bitArray &allRegsDefined) {
       
	assert(blockLiveInfo.find(block) != blockLiveInfo.end());
	livenessData &data = blockLiveInfo[block];
	data.out = bitArray(data.in.size());
	assert(data.out.size());
	// ignore call, return edges
	Intraproc epred;
	

    // OUT(X) = UNION(IN(Y)) for all successors Y of X
    boost::lock_guard<Block> g(*block);
    const Block::edgelist & target_edges = block -> targets();

    liveness_cerr << "getLivenessOut for block [" << hex << block->start() << "," << block->end() << "]" << dec << endl;
    

    std::for_each(boost::make_filter_iterator(epred, target_edges.begin(), target_edges.end()),
		  boost::make_filter_iterator(epred, target_edges.end(), target_edges.end()),
		  boost::bind(&LivenessAnalyzer::processEdgeLiveness, 
			      this, 
			      _1, 
			      boost::ref(data), 
			      block,
			      boost::ref(allRegsDefined)));
    
    liveness_cerr << " Returning liveness for out " << endl;
    liveness_cerr << "  " << data.out << endl;


    return data.out;
}

void LivenessAnalyzer::summarizeBlockLivenessInfo(Function* func, Block *block, bitArray &allRegsDefined) 
{
   if (blockLiveInfo.find(block) != blockLiveInfo.end()){
   	return;
   }
   liveness_printf("\tsummarize block info at block %lx\n", block->start());
 
   livenessData &data = blockLiveInfo[block];
   data.use = data.def = data.in = abi->getBitArray();

   using namespace Dyninst::InstructionAPI;
   Address current = block->start();
   InstructionDecoder decoder(
                       reinterpret_cast<const unsigned char*>(getPtrToInstruction(block, block->start())),		     
                       block->size(),
                       block->obj()->cs()->getArch());
   Instruction curInsn = decoder.decode();
   while(curInsn.isValid()) {
     ReadWriteInfo curInsnRW;
     liveness_printf("%s[%d] After instruction %s at address 0x%lx:\n",
                     FILE__, __LINE__, curInsn.format().c_str(), current);
     if(!cachedLivenessInfo.getLivenessInfo(current, func, curInsnRW))
     {
       curInsnRW = calcRWSets(curInsn, block, current);
       cachedLivenessInfo.insertInstructionInfo(current, curInsnRW, func);
     }

     data.use |= (curInsnRW.read & ~data.def);
     // And if written, then was defined
     data.def |= curInsnRW.written;
      
     liveness_printf("%s[%d] After instruction at address 0x%lx:\n",
                     FILE__, __LINE__, current);
     liveness_cerr << "        " << regs1 << endl;
     liveness_cerr << "        " << regs2 << endl;
     liveness_cerr << "        " << regs3 << endl;
     liveness_cerr << "Read    " << curInsnRW.read << endl;
     liveness_cerr << "Written " << curInsnRW.written << endl;
     liveness_cerr << "Used    " << data.use << endl;
     liveness_cerr << "Defined " << data.def << endl;

      current += curInsn.size();
      curInsn = decoder.decode();
   }

   liveness_printf("%s[%d] Liveness summary for block:\n", FILE__, __LINE__);
   liveness_cerr << "     " << regs1 << endl;
   liveness_cerr << "     " << regs2 << endl;
   liveness_cerr << "     " << regs3 << endl;
   liveness_cerr << "Used " << data.in << endl;
   liveness_cerr << "Def  " << data.def << endl;
   liveness_cerr << "Use  " << data.use << endl;
   liveness_printf("%s[%d] --------------------\n---------------------\n", FILE__, __LINE__);

   allRegsDefined |= data.def;

   return;
}

/* This is used to do fixed point iteration until 
   the in and out don't change anymore */
bool LivenessAnalyzer::updateBlockLivenessInfo(Block* block, bitArray &allRegsDefined) 
{
  bool change = false;
  livenessData &data = blockLiveInfo[block];

  // old_IN = IN(X)
  bitArray oldIn = data.in;
  // tmp is an accumulator
  getLivenessOut(block, allRegsDefined);
  
  // Liveness is a reverse dataflow algorithm
 
  // OUT(X) = UNION(IN(Y)) for all successors Y of X

  // IN(X) = USE(X) + (OUT(X) - DEF(X))
  liveness_cerr << "Updating block info for block " << hex << block->start() << dec << endl;
  liveness_cerr << "     " << regs1 << endl;
  liveness_cerr << "     " << regs2 << endl;
  liveness_cerr << "     " << regs3 << endl;
  liveness_cerr << "Out: " << data.out << endl;
  liveness_cerr << "Def: " << data.def << endl;
  liveness_cerr << "Use: " << data.use << endl;
  data.in = data.use | (data.out - data.def);
  liveness_cerr << "In:  " << data.in << endl;
  
  // if (old_IN != IN(X)) then change = true
  if (data.in != oldIn)
      change = true;
      
  return change;
}

// Calculate basic block summaries of liveness information

void LivenessAnalyzer::analyze(Function *func) {
    if (liveFuncCalculated.find(func) != liveFuncCalculated.end()) return;
    liveness_printf("Caculate basic block level liveness information for function %s (%lx)\n", func->name().c_str(), func->addr());

    // Step 0: initialize the "registers this function has defined" bitarray
    assert(funcRegsDefined.find(func) == funcRegsDefined.end());
    // Let's assume the regs that are normally live at the entry to a function
    // are the regs a call can read.
    funcRegsDefined[func] = abi->getCallReadRegisters();
    bitArray &regsDefined = funcRegsDefined[func];

    // Step 1: gather the block summaries
    Function::blocklist::iterator sit = func->blocks().begin();
    for( ; sit != func->blocks().end(); sit++) {
       summarizeBlockLivenessInfo(func,*sit, regsDefined);
    }
    
    // Step 2: We now have block-level summaries of gen/kill info
    // within the block. Propagate this via standard fixpoint
    // calculation
    bool changed = true;
    while (changed) {
        changed = false;
        for(sit = func->blocks().begin(); sit != func->blocks().end(); sit++) {
           if (updateBlockLivenessInfo(*sit, regsDefined)) {
                changed = true;
            }
        }
    }

    liveFuncCalculated[func] = true;
}


// This function does two things.
// First, it does a backwards iteration over instructions in its
// block to calculate its liveness.
// At the same time, we cache liveness (which was calculated) in
// any instPoints we cover. Since an iP only exists if the user
// asked for it, we take its existence to indicate that they'll
// also be instrumenting. 
bool LivenessAnalyzer::query(Location loc, Type type, bitArray &bitarray) {
//TODO: consider the trustness of the location 

   if (!loc.isValid()){
   	errorno = Invalid_Location;
	return false;
   }

   // First, ensure that the block liveness is done.
   analyze(loc.func);

   Address addr = 0;
   // For "pre"-instruction we subtract one from the address. This is done
   // because liveness is calculated backwards; therefore, accumulating
   // up to <addr> is actually the liveness _after_ that instruction, not
   // before. Since we compare using > below, -1 means it will trigger. 

   switch(loc.type) {
      // First, don't be dumb if we're looking at (effectively) an initial
      // instruction of a CFG element.
      case Location::function_:
      	 if (type == Before){
	 	bitarray = getLivenessIn(loc.func->entry());
		return true;
	 }
	 assert(0);
      case Location::block_:

      case Location::blockInstance_:
         
	 if (type == Before) {
	 	bitarray = getLivenessIn(loc.block);
		return true;
	 }
	 addr = loc.block->lastInsnAddr()-1;
	 break;

      case Location::instruction_:

      case Location::instructionInstance_:

         if (type == Before) {
	 	if (loc.offset == loc.block->start()) {
			bitarray = getLivenessIn(loc.block);
			return true;
		}
		addr = loc.offset - 1;
	 }
	 if (type == After) {
	 	if (loc.offset == loc.block->lastInsnAddr()) {
                   bitarray = blockLiveInfo[loc.block].out;
                   return true;
		}
	 	addr = loc.offset;
	}
	 break;

      case Location::edge_:
         bitarray = getLivenessIn(loc.edge->trg());
	 return true;
      case Location::entry_:
      	 if (type == Before) {
	 	bitarray = getLivenessIn(loc.block);
		return true;
	 }
	 assert(0);
      case Location::call_:
	 if (type == Before) addr = loc.block->lastInsnAddr()-1;
	 if (type == After) {
            bitarray = blockLiveInfo[loc.block].out;
            return true;
	 }
	 break;
      case Location::exit_:
      	 if (type == After){
	 	addr = loc.block->lastInsnAddr()-1;
		break;
	 }
	 assert(0);

      default:
         assert(0);
	 
  }
	
   // We know: 
   //    liveness _out_ at the block level:
   bitArray working = blockLiveInfo[loc.block].out;
   assert(!working.empty());

   // We now want to do liveness analysis for straight-line code. 
        
   using namespace Dyninst::InstructionAPI;
    
   Address blockBegin = loc.block->start();
   Address blockEnd = loc.block->end();
   std::vector<Address> blockAddrs;
   
   const unsigned char* insnBuffer = 
      reinterpret_cast<const unsigned char*>(getPtrToInstruction(loc.block, blockBegin));
   assert(insnBuffer);

   InstructionDecoder decoder(insnBuffer,loc.block->size(),
        loc.func->isrc()->getArch());
   Address curInsnAddr = blockBegin;
   do
   {
     ReadWriteInfo rw;
     if(!cachedLivenessInfo.getLivenessInfo(curInsnAddr, loc.func, rw))
     {
        Instruction tmp = decoder.decode(insnBuffer);
        rw = calcRWSets(tmp, loc.block, curInsnAddr);
        cachedLivenessInfo.insertInstructionInfo(curInsnAddr, rw, loc.func);
     }
     blockAddrs.push_back(curInsnAddr);
     curInsnAddr += rw.insnSize;
     insnBuffer += rw.insnSize;
   } while(curInsnAddr < blockEnd);
    
    
   // We iterate backwards over instructions in the block, as liveness is 
   // a backwards flow process.

   std::vector<Address>::reverse_iterator current = blockAddrs.rbegin();

   liveness_printf("%s[%d] instPoint calcLiveness: %d, 0x%lx, 0x%lx\n", 
                   FILE__, __LINE__, current != blockAddrs.rend(), *current, addr);
   
   while(current != blockAddrs.rend() && *current > addr)
   {
      ReadWriteInfo rwAtCurrent;
      if(!cachedLivenessInfo.getLivenessInfo(*current, loc.func, rwAtCurrent))
         assert(0);

      liveness_printf("%s[%d] Calculating liveness for iP 0x%lx, insn at 0x%lx\n",
                      FILE__, __LINE__, addr, *current);
      liveness_cerr << "Pre:    " << working << endl;
      working &= (~rwAtCurrent.written);
      working |= rwAtCurrent.read;
      liveness_cerr << "Post:   " << working << endl;
      liveness_cerr << "Current read:  " << rwAtCurrent.read << endl;
      liveness_cerr << "Current Write: " << rwAtCurrent.written << endl;
      
      ++current;
   }
   assert(!working.empty());


   bitarray = working;
   return true;
}

bool LivenessAnalyzer::query(Location loc, Type type, const MachRegister& machReg, bool &live){
	bitArray liveRegs;
	if (query(loc, type, liveRegs)){
        int index = getIndex(machReg);
        assert(index >= 0);
		live = liveRegs[index];
		return true;
	}
	return false;

}

void getReadSet(const Instruction& curInsn, std::set<InstructionAST::Ptr>& read_set){
    vector<Operand> operands;
    curInsn.getOperands(operands);
    for(auto cur_operand: operands)
    {
	cur_operand.getValue()->getUses(read_set);
    }
}


ReadWriteInfo LivenessAnalyzer::calcRWSets(Instruction curInsn, Block *blk, Address a)
{
  liveness_cerr << "calcRWSets for " << curInsn.format() << " @ " << hex << a << dec << endl;
  ReadWriteInfo ret;
  set<InstructionAST::Ptr> read_set;
  vector<RegisterAST*> read_regs;

  entryID what = curInsn.getOperation().getID();

  bool push_op = false;
  bool xor_op = false;
  bool pure_registers = true;


  ret.read = abi->getBitArray();
  ret.written = abi->getBitArray();
  ret.insnSize = curInsn.size();

  //if (isNopInsn(curInsn))
   //return ret;

  std::set<RegisterAST::Ptr> cur_read, cur_written;

  curInsn.getReadSet(cur_read);
  curInsn.getWriteSet(cur_written);


  switch (what){
      case e_push:
      case e_pushad:
      case e_pusha:
      case e_pushf:
      case e_pushfd:
	  push_op = true;
	  break;

      case e_pxor:
      case e_vpxor:
      case e_vxorpd:
      case e_vxorps:
      case e_vpxord:
      case e_vpxorq:
      case e_kxorb:
      case e_kxord:
      case e_kxorw:
      case e_kxorq:
      case e_xor:
      case e_xorpd:
      case e_xorps:
	  xor_op = true;
	  break;
  }

  // this is xor reg, reg
  // if the src and dst are same
  // discard the use register
  if (xor_op && !curInsn.readsMemory()){

      xor_op = false;

      getReadSet(curInsn, read_set);
      for (auto inst_ast : read_set){
	  RegisterAST* tmp;
	  if (tmp = dynamic_cast<RegisterAST*>(inst_ast.get())){
	      read_regs.push_back(tmp);
	  } else {
	      pure_registers = false;
	      break;
	  }
      }
      if (pure_registers && read_regs.size() == 2){
	  if (read_regs[0]->getID() == read_regs[1]->getID()){
	      xor_op = true;
	      //cout << hex << " addr: " << a << ", " << curInsn.format() << " delete!" << endl;
	  }
      }
  } else {
      xor_op = false;
  }


  liveness_printf("Read registers: \n");

  if (!push_op && !xor_op){
      for (std::set<RegisterAST::Ptr>::const_iterator i = cur_read.begin(); 
	   i != cur_read.end(); i++) 
      {
	MachRegister cur = (*i)->getID();
	if (cur.getArchitecture() == Arch_ppc64)
	    cur = MachRegister((cur.val() & ~Arch_ppc64) | Arch_ppc32);
	liveness_printf("\t%s \n", cur.name().c_str());
	MachRegister base = cur.getBaseRegister();
	if (base == x86::flags || base == x86_64::flags){
	  if (width == 4){
	    ret.read[getIndex(x86::of)] = true;
	    ret.read[getIndex(x86::cf)] = true;
	    ret.read[getIndex(x86::pf)] = true;
	    ret.read[getIndex(x86::af)] = true;
	    ret.read[getIndex(x86::zf)] = true;
	    ret.read[getIndex(x86::sf)] = true;
	    ret.read[getIndex(x86::df)] = true;
	    ret.read[getIndex(x86::tf)] = true;
	    ret.read[getIndex(x86::nt_)] = true;
	  }
	  else {
	    ret.read[getIndex(x86_64::of)] = true;
	    ret.read[getIndex(x86_64::cf)] = true;
	    ret.read[getIndex(x86_64::pf)] = true;
	    ret.read[getIndex(x86_64::af)] = true;
	    ret.read[getIndex(x86_64::zf)] = true;
	    ret.read[getIndex(x86_64::sf)] = true;
	    ret.read[getIndex(x86_64::df)] = true;
	    ret.read[getIndex(x86_64::tf)] = true;
	    ret.read[getIndex(x86_64::nt_)] = true;
	  }
	}
	else{
	  base = changeIfMMX(base);
	  int index = getIndex(base);
	  //assert(index >= 0);
	  if(index>=0) ret.read[index] = true;
    }
      }
  }
  liveness_printf("Write Registers: \n"); 
  for (std::set<RegisterAST::Ptr>::const_iterator i = cur_written.begin(); 
       i != cur_written.end(); i++) {  
    MachRegister cur = (*i)->getID();
    if (cur.getArchitecture() == Arch_ppc64)
	cur = MachRegister((cur.val() & ~Arch_ppc64) | Arch_ppc32);
    liveness_printf("\t%s \n", cur.name().c_str());
    MachRegister base = cur.getBaseRegister();
    if (base == x86::flags || base == x86_64::flags){
      if (width == 4){
        ret.written[getIndex(x86::of)] = true;
        ret.written[getIndex(x86::cf)] = true;
        ret.written[getIndex(x86::pf)] = true;
        ret.written[getIndex(x86::af)] = true;
        ret.written[getIndex(x86::zf)] = true;
        ret.written[getIndex(x86::sf)] = true;
        ret.written[getIndex(x86::df)] = true;
        ret.written[getIndex(x86::tf)] = true;
        ret.written[getIndex(x86::nt_)] = true;
      }
      else {
        ret.written[getIndex(x86_64::of)] = true;
        ret.written[getIndex(x86_64::cf)] = true;
        ret.written[getIndex(x86_64::pf)] = true;
        ret.written[getIndex(x86_64::af)] = true;
        ret.written[getIndex(x86_64::zf)] = true;
        ret.written[getIndex(x86_64::sf)] = true;
        ret.written[getIndex(x86_64::df)] = true;
        ret.written[getIndex(x86_64::tf)] = true;
        ret.written[getIndex(x86_64::nt_)] = true;
      }
    }
    else{
      base = changeIfMMX(base);
      int index = getIndex(base);
      //assert(index >= 0);
      if(index>=0){
          ret.written[index] = true;
          if ((cur != base && cur.size() < 4) || isMMX(base)) ret.read[index] = true;
      }
    }
  }

  InsnCategory category = curInsn.getCategory();
  switch(category)
  {
  case c_CallInsn:
      // Call instructions not at the end of a block are thunks, which are not ABI-compliant.
      // So make conservative assumptions about what they may read (ABI) but don't assume they write anything.
      //ret.read |= (abi->getCallReadRegisters());
      if(blk->lastInsnAddr() == a)
      {
          ret.written |= (abi->getCallWrittenRegisters());
      }
    break;
  case c_ReturnInsn:
    //ret.read |= (abi->getReturnReadRegisters());
    // Nothing written implicitly by a return
    break;
  case c_BranchInsn:
    if(!curInsn.allowsFallThrough() && isExitBlock(blk))
    {
      //Tail call, union of call and return
      //ret.read |= (abi->getCallReadRegisters());
		   //(abi->getReturnReadRegisters()));
      ret.written |= (abi->getCallWrittenRegisters());
    }
    break;
  default:
    {
      bool isInterrupt = false;
      bool isSyscall = false;


      if ((curInsn.getOperation().getID() == e_int) ||
	  (curInsn.getOperation().getID() == e_int3)) {
	isInterrupt = true;
      }
      static RegisterAST::Ptr gs(new RegisterAST(x86::gs));
      if (((curInsn.getOperation().getID() == e_call) &&
	   /*(curInsn()->getOperation().isRead(gs))) ||*/
	   (curInsn.getOperand(0).format(curInsn.getArch()) == "16")) ||
	  (curInsn.getOperation().getID() == e_syscall) ||
	  (curInsn.getOperation().getID() == e_int) ||
	  (curInsn.getOperation().getID() == power_op_sc)) {
	isSyscall = true;
      }

      if (curInsn.getOperation().getID() == power_op_svcs) {
	isSyscall = true;
      }
      if (curInsn.getOperation().getID() == aarch64_op_svc) {
          isSyscall = true;
      }
      if (isInterrupt || isSyscall) {
	ret.read |= (abi->getSyscallReadRegisters());
	ret.written |= (abi->getSyscallWrittenRegisters());
      }
    }
    break;
  }	  
  return ret;
}

void *LivenessAnalyzer::getPtrToInstruction(Block *block, Address addr) const{

	if (addr < block->start()) return NULL;
	if (addr > block->end()) return NULL;
	return block->region()->getPtrToInstruction(addr);
}
bool LivenessAnalyzer::isExitBlock(Block *block)
{
    boost::lock_guard<Block> g(*block);
    const Block::edgelist & trgs = block->targets();

    bool interprocEdge = false;
    bool intraprocEdge = false;
    for (Block::edgelist::const_iterator eit=trgs.begin(); eit != trgs.end(); ++eit){
        if ((*eit)->type() == CATCH) continue;
	if ((*eit)->interproc()) interprocEdge = true; else intraprocEdge = true;
    }

    if (interprocEdge && !intraprocEdge) return true; else return false;
}

void LivenessAnalyzer::clean(){

	blockLiveInfo.clear();
	liveFuncCalculated.clear();
	cachedLivenessInfo.clean();
}

void LivenessAnalyzer::clean(Function *func){

	if (liveFuncCalculated.find(func) != liveFuncCalculated.end()){		
		liveFuncCalculated.erase(func);
		Function::blocklist::iterator sit = func->blocks().begin();
		for( ; sit != func->blocks().end(); sit++) {
			blockLiveInfo.erase(*sit);
		}

	}
	if (cachedLivenessInfo.getCurFunc() == func) cachedLivenessInfo.clean();

}

bool LivenessAnalyzer::isMMX(MachRegister machReg){
	if ((machReg.val() & Arch_x86) == Arch_x86 || (machReg.val() & Arch_x86_64) == Arch_x86_64){
		assert( ((machReg.val() & x86::MMX) == x86::MMX) == ((machReg.val() & x86_64::MMX) == x86_64::MMX) );
		return (machReg.val() & x86::MMX) == x86::MMX;
	}
	return false;
}

MachRegister LivenessAnalyzer::changeIfMMX(MachRegister machReg){
	if (!isMMX(machReg)) return machReg;
	if (width == 4) return x86::mm0; else return x86_64::mm0;
}

