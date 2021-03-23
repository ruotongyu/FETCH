#ifndef CONSTANT_VISITOR_H
#define CONSTANT_VISITOR_H

#include "SymEval.h"
#include "DynAST.h"

#include "debug_parse.h"

#include "SymbolicExpression.h"

using namespace Dyninst;
using namespace Dyninst::DataflowAPI;

bool findConstant(SymbolicExpression& se, Result_t &res, NodeIterator exitBegin, NodeIterator exitEnd, Address &val){

    bool foundExit = false;
    bool ret = false;
    val = 0;
    bool mult = false;
    for ( ; exitBegin != exitEnd; exitBegin++) {
	
        Address curVal;

	Node::Ptr ptr = *exitBegin;
	SliceNode::Ptr aNode = boost::dynamic_pointer_cast<SliceNode>(ptr);
	Assignment::Ptr aAssign = aNode->assign();
	conditional_nonreturn_printf("[expandslice]: current assignment is %s\n", aAssign->format().c_str());
	DataflowAPI::Result_t::const_iterator iter = res.find(aAssign);
	if (iter == res.end()) return false;

	AST::Ptr p = iter->second;
	if (!p) return false;

	p = se.SimplifyAnAST(p, aAssign->addr());

	if (p->getID() == AST::V_ConstantAST) {
	    if (mult) {
		curVal = (Address)DataflowAPI::ConstantAST::convert(p)->val().val;
		if (curVal != val) {
		    conditional_nonreturn_printf("[expandslice]: find constant 0x%x, it different from before value 0x%x\n", curVal, val);
		    return false;
		}
	    } else {
		val = (Address)DataflowAPI::ConstantAST::convert(p)->val().val;
		conditional_nonreturn_printf("[expandslice]: find constant 0x%x\n", val);
		mult = true;
		ret = true;
	    }
    }
}

    return ret;
}

// reference: https://github.com/dyninst/tools/blob/e875854314432aba4a000409d25fb89631f4e1df/unstrip/fingerprint.C
bool ExpandSlice(GraphPtr slice, Address& val, SymbolicExpression& se) {
    Result_t res;
    SymEval::expand(slice, res);

    NodeIterator exitBegin, exitEnd;

    slice->allNodes(exitBegin, exitEnd);
    return findConstant(se, res, exitBegin, exitEnd, val);
}


#endif
