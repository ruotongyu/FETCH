#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <string.h>

#include "EhframeParser.h"

//#define DWARF_DEBUG

#define UNDEF_VAL 2000
#define SAME_VAL 2001
#define CFA_VAL 2002
#define INITIAL_VAL UNDEF_VAL

using namespace std;

void FrameParser::summary(){
    cerr << "================summary================" << endl;
    cerr << "The number of FDEs is " << _fde_cnt << endl;
    cerr << "The number of FDEs that has the information of stack height is " << _fde_stack_height_cnt << endl;
    cerr << "file path is " << f_path << ", rate is " << ((float)(_fde_stack_height_cnt)/(float)(_fde_cnt)) << endl;
    cerr << endl;
}

FrameParser::FrameParser(const char* _f_path){

    f_path = _f_path;

    if (strstr(_f_path, "ccr")){
	does_not_work = true;
    } else {
	does_not_work = false;
    }

    int fd = -1;
    int res = DW_DLV_ERROR;
    int regtabrulecount = 0;
    Dwarf_Error error;
    Dwarf_Handler errhand = 0;
    Dwarf_Ptr errarg = 0;
    //Dwarf_Debug dbg = 0;

    fd = open(f_path, O_RDONLY);

    if (fd < 0){
        std::cerr << "Can't open the file " << f_path << endl; 
	exit(-1);
    }

    _fde_cnt = 0;
    _fde_stack_height_cnt = 0;

    res = dwarf_init_b(fd, DW_DLC_READ, DW_GROUPNUMBER_ANY,
	    errhand, errarg, &_dbg, &error);

    if (res != DW_DLV_OK){
	cerr << "Parse dwarf error!" << endl;
	
	if (res == DW_DLV_ERROR){
	    cerr << "Error code " << dwarf_errmsg(error) << endl;
	}

	exit(-1);
    }

    /*
     * Do this setting after init before any real operations.
     * These return the old values, but here we do not
     * neeed to know the old values. The sizes and
     * values here are higher than most ABIs and entirely
     * arbitrary.
     *
     * The setting of initial_value
     * the same as undefined-value (the other possible choice being
     * same-value) is arbitrary, different ABIs do differ, and
     * you have to know which is right.
     *
     * In dwarfdump we get the SAME_VAL, UNDEF_VAL,
     * INITIAL_VAL CFA_VAL from dwconf_s struct.
     * */
    regtabrulecount = 1999;
    dwarf_set_frame_undefined_value(_dbg, UNDEF_VAL);
    dwarf_set_frame_rule_initial_value(_dbg, INITIAL_VAL);
    dwarf_set_frame_same_value(_dbg, SAME_VAL);
    dwarf_set_frame_cfa_value(_dbg, CFA_VAL);
    dwarf_set_frame_rule_table_size(_dbg, regtabrulecount);
    dwarf_get_address_size(_dbg, &_address_size, &error);

    if (_address_size != 4 && _address_size != 8){
	cerr << "Un-supported architecture " << _address_size << endl;
	exit(-1);
    }

    if (!iter_frame(_dbg)){
	cerr << "Can't parse eh_frame correctly!" << endl;
    }

    close(fd);
}

bool FrameParser::get_stack_height(Dwarf_Debug& dbg, Dwarf_Fde& fde, 
	Dwarf_Addr cur_addr, Dwarf_Error* error, signed& height){
    int res;
    Dwarf_Addr lowpc = 0;
    Dwarf_Unsigned func_length = 0;
    Dwarf_Regtable3 tab3;
    Dwarf_Unsigned fde_byte_length = 0;
    Dwarf_Signed cie_index = 0;
    Dwarf_Off cie_offset = 0;
    Dwarf_Off fde_offset = 0;
    Dwarf_Ptr fde_bytes;
    Dwarf_Half sp_reg = 0;
    Dwarf_Addr actual_pc = 0;
    struct Dwarf_Regtable_Entry3_s* cfa_entry = 0;
    struct Dwarf_Regtable_Entry3_s* sp_entry = 0;

    int oldrulecount = 0;

    res = dwarf_get_fde_range(fde, &lowpc, &func_length, &fde_bytes,
	    &fde_byte_length, &cie_offset, &cie_index, &fde_offset, error);

    if (res != DW_DLV_OK){
	cerr << "Problem getting fde range \n" << endl;
	return false;
    }

    if (cur_addr >= (lowpc + func_length) && cur_addr < lowpc){
	cerr << hex << cur_addr << " does not in current fde!";
	return false;
    }	

    /*
     * 1 is arbitrary. we are winding up getting the rule
     * count here while leaving things unchanged. */
    oldrulecount = dwarf_set_frame_rule_table_size(dbg, 1);
    dwarf_set_frame_rule_table_size(dbg, oldrulecount);

    tab3.rt3_reg_table_size = oldrulecount;
    tab3.rt3_rules = (struct Dwarf_Regtable_Entry3_s *) malloc (
	    sizeof(struct Dwarf_Regtable_Entry3_s) * oldrulecount);

    if (!tab3.rt3_rules){
	cerr << "unable to malloc for " << oldrulecount << " rules" << endl;
	return false;
    }

    res = dwarf_get_fde_info_for_all_regs3(fde, cur_addr, &tab3, &actual_pc, error);

    sp_reg = get_stack_pointer_id();

    if (res != DW_DLV_OK){
	cerr << "dwarf_get_fde_info_for_all_regs3 failed" << endl;
	return false;
    }
    
    if (sp_reg >= tab3.rt3_reg_table_size){
	cerr << "sp(" << sp_reg << ") is bigger than rt3_reg_table_size " 
	    << tab3.rt3_reg_table_size << endl;
	return false;
    }
    cfa_entry = &tab3.rt3_cfa_rule;
    parse_one_regentry(cfa_entry, height);
    free(tab3.rt3_rules);
    return true;
}

bool FrameParser::parse_one_regentry(struct Dwarf_Regtable_Entry3_s *entry, signed& height){
    Dwarf_Unsigned offset = 0xffffffff;
    Dwarf_Half reg = 0xffff;
#ifdef DWARF_DEBUG
    cout << "type: " << " " <<
	((entry->dw_value_type == DW_EXPR_OFFSET) ? "DW_EXPR_OFFST" :
	(entry->dw_value_type == DW_EXPR_VAL_OFFSET) ? "DW_EXPR_VAL_OFFSET" : 
	(entry->dw_value_type == DW_EXPR_EXPRESSION) ? "DW_EXPR_EXPRESSION" :
	(entry->dw_value_type == DW_EXPR_VAL_EXPRESSION) ? "DW_EXPR_VAL_EXPRESSION" : "Unknown") << endl;
#endif
    switch(entry->dw_value_type) {
	case DW_EXPR_OFFSET:
	    reg = entry->dw_regnum;
	    if (entry->dw_offset_relevant){
		offset = entry->dw_offset_or_block_len;
	    }
	    break;
	default:
	    cerr << "Can't handle the type " << entry->dw_value_type << " of cfa definition!" << endl;
	    break;
    }

    if (offset == 0xffffffff || reg == 0xffff){
	cerr << "Can't get the register or offset!" << endl;
	return false;
    }

    if (reg != get_stack_pointer_id()){
	cerr << "Wired. CFA is not defined based on stack pointer register(rsp/esp)" << endl;
	return false;
    }
    
    height = offset;
    return true;
}


bool FrameParser::parse_fde(Dwarf_Debug dbg, Dwarf_Fde fde, Dwarf_Signed fde_num, Dwarf_Error* error){
    int res;
    Dwarf_Addr lowpc = 0;
    Dwarf_Addr idx_i = 0;
    Dwarf_Unsigned func_length = 0;
    Dwarf_Ptr fde_bytes;
    Dwarf_Unsigned fde_bytes_length = 0;
    Dwarf_Off cie_offset = 0;
    Dwarf_Signed cie_index = 0;
    Dwarf_Off fde_offset = 0;
    Dwarf_Addr arbitrary_addr = 0;
    Dwarf_Addr actual_pc = 0;
    Dwarf_Addr end_func_addr = 0;

    int oldrulecount = 0;
    Dwarf_Ptr outinstrs = 0;
    Dwarf_Unsigned instrslen = 0;
    Dwarf_Frame_Op* frame_op_array = 0;
    Dwarf_Signed frame_op_count = 0;
    Dwarf_Cie cie = 0;

    bool is_sp_based = false;

    res = dwarf_get_fde_range(fde, &lowpc, &func_length, &fde_bytes,
	    &fde_bytes_length, &cie_offset, &cie_index, &fde_offset, error);

#ifdef DWARF_DEBUG
    cerr << " FDE: " << hex << lowpc << " -> " << lowpc + func_length << endl; 
#endif

    _fde_cnt++;

    if (res != DW_DLV_OK) {
	cerr << "Problem getting fde range " << endl;
	return false;
    }

    res = dwarf_get_fde_instr_bytes(fde, &outinstrs, &instrslen, error);

    if (res != DW_DLV_OK){
	cerr << "dwarf_get_fde_instr_bytes failed!" << endl;
	return false;
    }

    res = dwarf_get_cie_of_fde(fde, &cie, error);

    if (res != DW_DLV_OK){
	cerr << "Error getting cie from fde" << endl;
	return false;
    }

    res = dwarf_expand_frame_instructions(cie, outinstrs, instrslen,
	    &frame_op_array, &frame_op_count, error);

    if (res != DW_DLV_OK){
	cerr << "dwarf_expand_frame_instructions failed!" << endl;
	return false;
    }

    // iter over every instruction, to check every definition of cfas
    is_sp_based = check_cfa_def(frame_op_array, frame_op_count);
    if (!is_sp_based){

#ifdef DWARF_DEBUG
	cerr << "In func " << hex << lowpc <<  ", the definion of cfa is not defined by rsp/esp!" << endl; 
#endif
    } else {
	_fde_stack_height_cnt++;
    }

    frames.insert(FrameData(lowpc, is_sp_based, func_length, fde_num));

    dwarf_dealloc(dbg, frame_op_array, DW_DLA_FRAME_BLOCK);
    return true;
}

signed FrameParser::request_stack_height(uint64_t cur_addr, signed &height){

    if (does_not_work)
	return HEIGHT_DOES_NOT_WORK_ERROR;

    // check if current address is in the range of eh_frame
    FrameData* cur_frame = nullptr;
    Dwarf_Error error;
    for (auto frame: frames){
	if (frame.in_range(cur_addr)){
	    cur_frame = &frame;
	    break;
	}

	// can't find a proper frame
	if (cur_addr < frame.get_pc()){
	    break;
	}
    }
    if (!cur_frame)
	return HEIGHT_ERROR_CANT_FIND;

    if (!cur_frame->get_cfa_offset_sp())
	return HEIGHT_ERROR_NOT_BASED_ON_SP;

    // ok. get the stack height
    if (!get_stack_height(_dbg, _fde_data[cur_frame->get_fde_num()], cur_addr, &error, height)){
	return HEIGHT_ERROR;
    }

    return 0;

}

short unsigned int FrameParser::get_stack_pointer_id(){
    if (_address_size == 4)
	return 4;
    else
	return 7;
}

bool FrameParser::check_cfa_def(Dwarf_Frame_Op* frame_op_array, Dwarf_Signed frame_op_count){
    Dwarf_Signed i = 0;

    bool res = true;

    for (i; i < frame_op_count; ++i){
	Dwarf_Frame_Op *fo = frame_op_array + i;
	switch (fo->fp_extended_op){

	    case DW_CFA_def_cfa:
	    case DW_CFA_def_cfa_sf:
	    case DW_CFA_def_cfa_register:
		// TODO. check if the regiseter is rsp/esp
		//fo->fp_register
		if (_address_size == 8){
		    if (fo->fp_register != 7){
			res = false;
		    }
		} else {
		    if (fo->fp_register != 4){
			res = false;
		    }
		}
		break;
	    
	    // TODO. Handle it. can't handle this now.
	    case DW_CFA_def_cfa_expression:
		res = false;
		break;
	}
    }
    return res;
}

bool FrameParser::iter_frame(Dwarf_Debug dbg){
    Dwarf_Error error;

    int res = DW_DLV_ERROR;
    Dwarf_Signed fdenum = 0;

    res = dwarf_get_fde_list_eh(dbg, &_cie_data, &_cie_element_count,
	    &_fde_data, &_fde_element_count, &error);

    if (res == DW_DLV_NO_ENTRY){
	cerr << "No .eh_frame section!" << endl;
	return false;
    }

    if (res == DW_DLV_ERROR){
	cerr << "Error reading frame data! " << endl;
	return false;
    }

#ifdef DWARF_DEBUG
    cerr << _cie_element_count << " cies present. "
	<< _fde_element_count << " fdes present. \n" << endl;
#endif

    for (fdenum = 0; fdenum < _fde_element_count; ++fdenum){
	Dwarf_Cie cie = 0;

	res = dwarf_get_cie_of_fde(_fde_data[fdenum], &cie, &error);

	if (res != DW_DLV_OK) {
	    cerr << "Error accessing cie of fdenum " << fdenum 
		<< " to get its cie" << endl;
	    return false;
	}

#ifdef DWARF_DEBUG
    cerr << " Print cie of fde " << fdenum << endl;
#endif

    // parse every fde
    parse_fde(dbg, _fde_data[fdenum], fdenum, &error);

#ifdef DWARF_DEBUG
    cerr << " Print fde " << fdenum << endl;
#endif

    }

    return true;
}

FrameParser::~FrameParser(){
    Dwarf_Error error;
    dwarf_fde_cie_list_dealloc(_dbg, _cie_data, _cie_element_count,
	    _fde_data, _fde_element_count);

    auto res = dwarf_finish(_dbg, &error);
    if (res != DW_DLV_OK){
	cerr << "dwarf_finish failed\n" << endl;
    }

}
