#ifndef CONSTANT_PRED_H
#define CONSTANT_PRED_H

#include "Instruction.h"
#include "InstructionDecoder.h"
#include "slicing.h"
#include "Register.h"

using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;
using namespace DataflowAPI;

class ConstantPred : public Slicer::Predicates {
  public:
      bool addPredecessor(AbsRegion reg)
        {
            Absloc esp_reg(x86_64::rsp);
            return !(reg.contains(esp_reg));
        }

        bool endAtPoint(AssignmentPtr assign)
        {
            AbsRegion & out = (*assign).out();
            Absloc esp_reg(x86_64::rsp);
            return out.contains(esp_reg);
        }
};

#endif
