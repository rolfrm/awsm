#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <stdarg.h>
#include "wasm_instr.h"
#include "awsm.h"
#include "awsm_internal.h"


void dwarf_debug_line_state_machine_reset(dwarf_debug_line_state_machine * sm, bool address){
  sm->column = 0;
  sm->line = 1;
  sm->op_index = 0;
  sm->prologue_end = true;
  sm->is_stmt = sm->default_is_stmt;
  if(address){
    sm->address = 0;
    sm->file = 1;
  }
}

void dwarf_debug_line_advance(dwarf_debug_line_state_machine * sm, i32 amount, bool incr_line){
  u32 advance = amount / sm->line_range;
  u32 new_address = sm->address + (sm->op_index + advance) / sm->maxmium_ops_per_instr;
  u32 new_op_index = (sm->op_index + advance) % sm->maxmium_ops_per_instr;
  
  sm->address = new_address;
  sm->op_index = new_op_index;
  if(incr_line){
    sm->prev_line = sm->line;
    u32 line_increment = sm->line_base + (amount % sm->line_range);
    sm->line += line_increment;
  }
}

bool dwarf_debug_line_commit_row(dwarf_debug_line_state_machine * sm, u32 code_offset, char * out_filename, int * out_line){
  UNUSED(out_filename);
  //printf("             ROW: %x %i %i    %i %i\n", sm->address, sm->line, sm->column,  sm->prologue_end, sm->is_stmt);

  if(code_offset <= sm->address){
    const u8 * file = sm->files;
    for(u32 i = 0; i < sm->file - 1; i++){
      while(*file != 0){
	file = file + 1;
      }
    }
    strcpy(out_filename, (char *) file);

    
    *out_line = sm->prev_line;
    return true;
  }
  return false;
}

int dwarf_source_location(u8 * dwarf_code, u32 code_size, u32 code_offset, char * out_filename, int * out_line){
  wasm_code_reader _rd = { .data = dwarf_code, .offset = 0, .size = code_size};
  wasm_code_reader * rd = &_rd;
  
  dwarf_debug_line_state_machine sm = {0};
  //reader_read1(rd);
  u32 length = reader_readu32_fixed(rd);
  u16 version = reader_readu16_fixed(rd);
  ASSERT(version == 4);
  u32 prolog_length = reader_readu32_fixed(rd);
  UNUSED(prolog_length);
  UNUSED(length);
  sm.minimum_instr_length = reader_read1(rd);
  sm.maxmium_ops_per_instr = reader_read1(rd);
  sm.default_is_stmt = reader_read1(rd);
  sm.line_base = (i8)reader_read1(rd);
  sm.line_range = reader_read1(rd);
  u8 opcode_base = reader_read1(rd);
  u32 opcode_lengths[opcode_base];
  opcode_lengths[0] = 0;
  for(u8 i = 1 ;i < opcode_base; i++){
    opcode_lengths[i] = reader_readu32(rd);
  }
  UNUSED(opcode_lengths);
  UNUSED(version);
  
  //printf("DWARF %i %i %i %i %i %i\n", length, code_size, version, prolog_length, sm.minimum_instr_length, sm.maxmium_ops_per_instr);
  //printf("      %i %i %i %i \n" ,sm.default_is_stmt, sm.line_base, sm.line_range, opcode_base);
  //printf("\n      ");
  //for(u8 i = 0; i < opcode_base; i++){
  //  printf( "%i ", opcode_lengths[i]);
  //}
  //printf("\n");
  while(true){
    // read the dir names  ( unused )x;
    u8 check = reader_read1(rd);
    if(check == 0)
      break;
    while(reader_read1(rd) != 0){  }
  }

  u8 * file_start;
  file_start = rd->data + rd->offset;
  
  while(true){
    // read the file names ( unused )
    u8 check = reader_read1(rd);
    if(check == 0){

      break;
    }
    while(reader_read1(rd) != 0){

    }
    //u32 offset2 = rd->offset;

    u32 dir = reader_readu32(rd);
    u32 modified = reader_readu32(rd);
    u32 filelen = reader_readu32(rd);
    UNUSED(dir);UNUSED(modified);UNUSED(filelen);
    //printf("FILE: %s %i %i %i\n", rd->data + offset1, dir, modified, filelen);
  }

  //u32 opcode = (1 - line_base) + (line_range * 1) + opcode_base;
  //printf("opcode: %i\n", opcode - opcode_base);


  dwarf_debug_line_state_machine_reset(&sm, true);
  sm.files = file_start;
  
  //u32 column =0, line = 1, address = 0, op_index = 0;;
  //bool prologue_end = true, is_stmt = default_is_stmt;
  bool end = false;
  for(int i = 0; i < 100000; i++){
    if(rd->offset ==rd->size || end)
      break;
    u8 opcode = reader_read1(rd);
    //printf("opcode %i\n", opcode);
    
    switch(opcode){
    case 0: // extended opcode
      {
	u32 len = reader_readu32(rd);
	u8 code = reader_read1(rd);

	switch(code){
	case 0:
	  printf("ERROR!!\n");
	  break;
	  case 1: //DW_LNE_end_sequence
	    {
	      end = dwarf_debug_line_commit_row(&sm, code_offset, out_filename, out_line);
	      dwarf_debug_line_state_machine_reset(&sm, false);
	      break;
	    }
	    
	case 2: //DW_LNE_set_address  
	  {
	    u32 addr = reader_readu32_fixed(rd);
	    //printf("SET ADDRESS: %i\n", addr);
	    sm.address = addr;
	    sm.op_index = 0;
	    break;
	  }
	  
	case 3: //DW_LNE_define_file 
	  {
	    
	    break;
	  }
	case 4:{ // DW_LNE_set_discriminator
	  
	  break;
	}
	default:{
	  ERROR("Unsupported extended opcode %i\n", code);
	  break;

	}
	}
	UNUSED(len);
	//printf("EXT: %i %i\n", len, code);
	break;
      }
    case 1: //DW_LNS_copy
      {
	end = dwarf_debug_line_commit_row(&sm, code_offset, out_filename, out_line);
	sm.prologue_end = false;
	break;
      }
    case 2: // advance pc
      {

	u32 adjusted = reader_readu32(rd);
	dwarf_debug_line_advance(&sm, adjusted, false);
	break;
      }

    case 3: //Advance Line
      {
	i32 count = reader_readi32(rd);
	sm.line += count;
	break;
      }
    case 5: //DW_LNS_set_column
      {
	sm.column = reader_readu32(rd);
	break;
      }
    case 6:{ //negate stmt
      sm.is_stmt = !sm.is_stmt;
      break;
    }

    case 8:{ //DW_LNS_const_add_pc 

	dwarf_debug_line_advance(&sm, 255, false);
	break;
    }

    case 10: // set prologue end
      {
	sm.prologue_end = true;
	break;
      }
    default:

      if(opcode > opcode_base){
	u32 adjusted = opcode - opcode_base;
	dwarf_debug_line_advance(&sm, adjusted, true);
	end = dwarf_debug_line_commit_row(&sm, code_offset, out_filename, out_line);
	sm.prologue_end = false;
      }
      else{
	ERROR("ERR");
      }
      break;

    }
    if(end)
      break;
  }

  if(end) return 0;
  return 1;
}
