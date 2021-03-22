#ifndef EHFRAME_PARSER_H
#define EHFRAME_PARSER_H

#include "dwarf.h"
#include "libdwarf.h"
#include <stdint.h>
#include <map>
#include <set>

#define HEIGHT_ERROR_NOT_BASED_ON_SP -1
#define HEIGHT_ERROR_CANT_FIND -2
#define HEIGHT_ERROR -3
#define HEIGHT_DOES_NOT_WORK_ERROR -4

class FrameData{
    private:
	bool _cfa_offset_sp; // is cfa offset to stack pointer in current frame
	uint64_t _lowpc;
	uint64_t _size;
	signed _fde_num;

	std::map<uint64_t, int32_t> frame_pointers; // stores the changing point of frame pointer
	
    public:

	FrameData(uint64_t pc, bool cfa_offset_sp, uint64_t size, signed fde_num):
	_lowpc(pc), _cfa_offset_sp(cfa_offset_sp), _size(size), _fde_num(fde_num){
	}

	signed get_fde_num() const {return _fde_num;}
	uint64_t get_pc() const {return _lowpc; }

	bool in_range(uint64_t addr) { 
	    if (addr >= _lowpc && addr < _lowpc + _size) 
		return true; 
	    return false;
	}

	bool operator== (const FrameData& r_hs) const {
	    return _lowpc == r_hs.get_pc();
	}

	bool operator< (const FrameData& r_hs) const {
	    return _lowpc < r_hs.get_pc();
	}

	bool operator> (const FrameData& r_hs) const {
	    return _lowpc > r_hs.get_pc();
	}

	std::map<uint64_t, int32_t>* get_frame_pointers(){
	    return &frame_pointers;
	}

	void insert_frame_pointer(uint64_t addr, int32_t height){
	    frame_pointers[addr] = height;
	}

	bool get_cfa_offset_sp() const {return _cfa_offset_sp;}

	int32_t get_height(uint64_t addr);

};

class FrameParser{

    private:
	std::set<FrameData> frames;

	short unsigned int _address_size;
	short unsigned int get_stack_pointer_id();

	Dwarf_Signed _cie_element_count;
	Dwarf_Signed _fde_element_count;
	Dwarf_Cie *_cie_data;
	Dwarf_Fde *_fde_data;
	Dwarf_Debug _dbg;

	bool iter_frame(Dwarf_Debug);

	bool parse_fde(Dwarf_Debug, Dwarf_Fde, Dwarf_Signed, Dwarf_Error*);

	bool check_cfa_def(Dwarf_Frame_Op*, Dwarf_Signed);

	bool get_stack_height(Dwarf_Debug&, Dwarf_Fde&, Dwarf_Addr, Dwarf_Error*, signed&);

	bool parse_one_regentry(struct Dwarf_Regtable_Entry3_s*, signed&);


	signed _fde_cnt;
	signed _fde_stack_height_cnt;
	const char* f_path;

	bool does_not_work;
    
    public:
	FrameParser(const char*);
	void summary();

	// ret val:
	// HEIGHT_ERROR_CANT_FIND: can't find eh_frame that contains cur_addr
	// HEIGHT_ERROR_NOT_BASED_ON_SP: the CFA is not based on SP registers
	// HEIGHT_ERROR: other errors
	// 0: get height successfully
        signed request_stack_height(uint64_t cur_addr, signed& height);
	~FrameParser();

};
#endif
