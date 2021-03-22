#ifndef DETECT_TAIL_CALL_H
#define DETECT_TAIL_CALL_H

#include "CodeObject.h"
#include <map>
#include <cstdint>
#include "stackanalysis.h"
#include "../stackheight/ehframe/EhframeParser.h"

using namespace Dyninst;
class tailCallAnalyzer{
    private:
	ParseAPI::CodeObject* codeobj;
	std::map<uint64_t, uint64_t>* refs;
	FrameParser *frame_parser;
	std::map<uint64_t, uint64_t>* funcs_range;
	const char* f_path;

	uint64_t cached_func;
	StackAnalysis* cached_sa;

	bool getStackHeight(uint64_t address, ParseAPI::Function* func, ParseAPI::Block* block, int32_t& height, bool);

    public:
	tailCallAnalyzer(ParseAPI::CodeObject* co, std::map<uint64_t, uint64_t>* refs, std::map<uint64_t, uint64_t>* funcs_range, const char* f_path);
	void analyze(std::map<uint64_t, uint64_t>&, bool);
	virtual ~tailCallAnalyzer();

};
void detectTailcall(Dyninst::ParseAPI::CodeObject* codeobj, std::map<uint64_t, uint64_t> refs); 
#endif
