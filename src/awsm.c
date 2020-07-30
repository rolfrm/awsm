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

void awsm_set_error_callback(void (*f)(const char * file, int line, const char * msg, ...)){
  _error = f;
}

bool awsm_log_diagnostic = false;

void logd(const char * msg, ...){
UNUSED(msg);
#ifdef DEBUG

  if(awsm_log_diagnostic){
    va_list arglist;
    va_start (arglist, msg);
    vprintf(msg,arglist);
    va_end(arglist);
  }
#endif
}

static void _log(const char * msg, ...){
  va_list arglist;
  va_start (arglist, msg);
  vprintf(msg,arglist);
  va_end(arglist);
}

static void * alloc0(size_t size){
  void * ptr = malloc(size);
  memset(ptr, 0, size);
  return ptr;
}

static void * alloc(size_t size){
  return alloc0(size);
}

static void dealloc(void * ptr){
  free(ptr);
}

static void * mem_clone(const void * ptr, size_t s){
  void * new = alloc(s);
  memcpy(new, ptr, s);
  return new;
}

static void * read_stream_to_buffer(FILE * f, size_t * size){
  if(f == NULL)
    return NULL;
  fseek(f,0,SEEK_END);
  *size = ftell(f);
  char * buffer = alloc0(*size + 1);
  fseek(f, 0, SEEK_SET);
  size_t l = fread(buffer,*size,1,f);
  ASSERT(l == 1);
  return buffer;
}

static void * read_file_to_buffer(const char * filepath, size_t * size){
  FILE * f = fopen(filepath, "r");
  if(f == NULL) return NULL;
  char * data = read_stream_to_buffer(f, size);
  fclose(f);
  return data;
}


static void wasm_heap_min_capacity(wasm_heap * heap, size_t capacity){
  if(heap->capacity < capacity){
    size_t old_capacity = capacity;
    heap->heap = realloc(heap->heap, capacity);
    memset(heap->heap + old_capacity, 0, capacity - old_capacity);
    heap->capacity = capacity;
  }
}

size_t awsm_heap_size(wasm_module * mod){
  return mod->heap->capacity;
}

void awsm_heap_increase(wasm_module * mod, size_t amount){
  wasm_heap_min_capacity(mod->heap, mod->heap->capacity + amount);
}

static size_t wasm_module_add_func(wasm_module * module){
  module->func_count += 1;
  module->func = realloc(module->func, module->func_count * sizeof(module->func[0]));;
  module->func[module->func_count - 1] = (wasm_function){0};
  return module->func_count - 1;
}

// todo: Many of these operations can be optimized, by modifying the top of the stack in-place.

#define BINARY_OP(type, op){			\
    type a = {0}, b = {0};			\
    wasm_pop_##type##_2(ctx, &b, &a);		\
    wasm_push_##type(ctx, a op b);		\
    logd("%p " #op " %p\n", a, b);		\
  }break;

#define BINARY_OP_U64(type, op){\
    type a = {0}, b = {0};			\
    wasm_pop_##type##_2(ctx, &b, &a);		\
    wasm_push_i32(ctx, (i32)(a op b));		\
    logd("%p " #op " %p\n", a, b);		\
  }break;

#define BINARY_OPF(type, op){			\
    type a = {0}, b = {0};			\
    wasm_pop_##type##_2(ctx, &a, &b);		\
    wasm_push_##type(ctx, op(a, b));		\
    logd("%f " #op " %f\n", a, b);		\
  }break;

#define UNARY_OPF(type, f){			\
    type a = {0};				\
  wasm_pop_##type(ctx, &a);			\
  wasm_push_##type(ctx, f(a));			\
  logd("%f " #f "\n", a);			\
  }break;

#define CAST_OP(typea, typeb){			\
    typea a = {0};				\
    wasm_pop_##typea(ctx, &a);			\
    wasm_push_##typeb(ctx, (typeb)a);		\
  }break;

#define OP_NEG(x)-x
#define OP_EQZ(x)x == 0
#define TRUNCF_I32(X) (i32)(truncf(X))
#define TRUNCF_U32(X) (u32)(truncf(X))
#define TRUNCD_I32(X) (i32)(trunc(X))
#define TRUNCD_U32(X) (u32)(trunc(X))
#define TRUNCF_I64(X) (i64)(truncf(X))
#define TRUNCF_U64(X) (u64)(truncf(X))
#define TRUNCD_I64(X) (i64)(trunc(X))
#define TRUNCD_U64(X) (u64)(trunc(X))
#define EXTEND_I64_I32(x) (u64)x
#define EXTEND_I64_U32(x) (u64)x
#define CONVERT_TO_F32(x) (f32)x
#define CONVERT_TO_F64(x) (f64)x
#define UNSUPPORTED_OP(name){ ERROR("Unsupported operation\n"); } break;

void reader_advance(wasm_code_reader * rd, size_t bytes){
  ASSERT(rd->offset + bytes <= rd->size);
  rd->offset += bytes;
}

u8 reader_read1(wasm_code_reader * rd){
  u8 b = ((u8 *)(rd->data + rd->offset))[0];
  reader_advance(rd, 1);
  return b;
}

u8 reader_peek1(wasm_code_reader * rd){
  u8 b = ((u8 *)(rd->data + rd->offset))[0];
  return b;
}

void reader_read(wasm_code_reader * rd, void * buffer, size_t len){
  ASSERT(rd->offset + len <= rd->size);
  memcpy(buffer, rd->data + rd->offset, len);
  reader_advance(rd, len);
}

u64 reader_readu64(wasm_code_reader * rd){
  // read LEB128
  u8 chunk = 0;
  u64 value = 0;
  u32 offset = 0;
  while((chunk = reader_read1(rd)) > 0){
    value |= (0b01111111L & chunk) << offset;
    offset += 7;
    if((0b10000000L & chunk) == false)
      break;
  }
  return value;
}

u32 encode_u64_leb(u64 value, u8 * buffer){
  u8 * b1 = buffer;
     
  do{
    *buffer = value & 0b01111111L;
    value >>= 7;
    if(value)
      *buffer |= 0b10000000L;
    buffer += 1;
  }while(value > 0);
  return buffer - b1;
}

u32 reader_readu32(wasm_code_reader * rd){
  return reader_readu64(rd);
}

u64 reader_readu64_fixed(wasm_code_reader * rd){
  u64 value;
  reader_read(rd, &value, sizeof(value));
  return value;
}


i32 reader_readi32_fixed(wasm_code_reader * rd){
  i32 value;
  reader_read(rd, &value, sizeof(value));
  return value;
}

u32 reader_readu32_fixed(wasm_code_reader * rd){
  u32 value;
  reader_read(rd, &value, sizeof(value));
  return value;
}

u16 reader_readu16_fixed(wasm_code_reader * rd){
  u16 value;
  reader_read(rd, &value, sizeof(value));
  return value;
}


f32 reader_readf32(wasm_code_reader * rd){
  f32 v = 0;
  memcpy(&v, rd->data + rd->offset, sizeof(v));
  reader_advance(rd, sizeof(v));
  return v;
}

f64 reader_readf64(wasm_code_reader * rd){
  f64 v = 0;
  reader_read(rd, &v, sizeof(v));
  return v;
}

i64 reader_readi64(wasm_code_reader * rd) {
    // read LEB128
  i64 value = 0;
  u32 shift = 0;
  u8 chunk;
  do {
    chunk = reader_read1(rd);
    value |= (((u64)(chunk & 0x7f)) << shift);
    shift += 7;
  } while (chunk >= 128);
  if (shift < 64 && (chunk & 0x40))
    value |= (-1ULL) << shift;
  return value;
}

i32 reader_readi32(wasm_code_reader * rd){
  return (i32)reader_readi64(rd);
}

size_t reader_getloc(wasm_code_reader * rd){
  return rd->offset;
}
  
char * reader_readname(wasm_code_reader * rd){
  u32 len = reader_readu32(rd);
  char * buffer = alloc(len + 1);
  reader_read(rd, buffer, len);
  buffer[len] = 0;
  return buffer;
}

static wasm_instr move_to_end_of_block(wasm_code_reader * rd, u32 block){
  u32 blk = block;
  while(rd->offset < rd->size){
    wasm_instr instr = reader_read1(rd);
    logd("SKIP INSTR: %x\n", instr);
    if(instr >= WASM_INSTR_LOCAL_GET && instr <= WASM_INSTR_GLOBAL_SET)
      {
	// all these has one integer.
	reader_readu64(rd);
	continue;
      }
    if(instr >= WASM_INSTR_I32_LOAD && instr <= WASM_INSTR_I64_STORE_32){
      reader_readi64(rd);
      reader_readi64(rd);
      continue;
    }
    if(instr >= WASM_INSTR_MEMORY_SIZE && instr <= WASM_INSTR_I64_CONST){
      reader_readi64(rd);
      continue;
    }
      
    if(instr >= WASM_INSTR_I32_EQZ && instr <= WASM_INSTR_F64_REINTERPRET_I64){
      continue;
    }
    //f32/64 const 
      
    switch(instr){
    case WASM_INSTR_SELECT:
    case WASM_INSTR_DROP:
    case WASM_INSTR_UNREACHABLE:
    case WASM_INSTR_NOP:
      break;
    case WASM_INSTR_BLOCK:
    case WASM_INSTR_LOOP:
    case WASM_INSTR_IF:
      reader_read1(rd);
      blk += 1;
      break;
    case WASM_INSTR_END:
      if(block == blk)
	return instr;
      blk -= 1;
      break;
    case WASM_INSTR_ELSE:
      if(block == blk)
	return instr;
      break;
    case WASM_INSTR_BR:
    case WASM_INSTR_BR_IF:
      reader_readu32(rd);
      break;
    case WASM_INSTR_BR_TABLE:
      {
	u32 c = reader_readu32(rd);
	for(u32 i = 0; i < c; i++)
	  reader_readu32(rd);
	reader_readu32(rd);
      }break;
    case WASM_INSTR_RETURN:
      break; // dont return while skip block
    case WASM_INSTR_CALL:
      reader_readu32(rd);
      break;
    case WASM_INSTR_CALL_INDIRECT:
      reader_readu32(rd);
      reader_read1(rd);
      break;
    case WASM_INSTR_F32_CONST:
      reader_advance(rd, sizeof(f32));
      break;
    case WASM_INSTR_F64_CONST:
      reader_advance(rd, sizeof(f64));
      break;
    default:
      ERROR("Unhandled instruction %x\n", instr);
    }
  }
  return WASM_INSTR_UNREACHABLE;
}

// Load a WASM module from bytes
wasm_module * load_wasm_module(wasm_heap * heap, wasm_code_reader * rd){
  wasm_module module = {0};
  module.steps_per_context_switch = AWSM_DEFAULT_STEPS_PER_CONTEXT_SWITCH;
  module.heap = heap;
  ASSERT(rd->size > 8);
   
  const char * magic_header_test = "\0asm";
  char magic_header[4];
  reader_read(rd, magic_header, sizeof(magic_header));
  bool contains_magic = memcmp(magic_header_test, magic_header, 4) == 0;
  if(contains_magic == false){
    ERROR("WASM data does not contain correct header");
    return NULL;
  }

  const u8 wasm_version_test[]  = {1,0,0,0};
  char wasm_version[4];
  reader_read(rd, wasm_version, sizeof(wasm_version));
  bool contains_version = memcmp(wasm_version,wasm_version_test, sizeof(wasm_version)) == 0;
  if(contains_version == false){
    ERROR("WASM data does not contain correct header");
    return NULL;
  }
  
  while(rd->offset < rd->size){
    wasm_section section = (wasm_section) reader_read1(rd);
    logd(" %i: ", section);
    switch(section){
    case WASM_CUSTOM_SECTION:
      logd("WASM CUSTOM SECTION\n");
      {
	u32 length = reader_readu32(rd);
	u32 offset_pre = rd->offset ;
	char * name = reader_readname(rd);
	u32 namelen = rd->offset - offset_pre;
	u32 sectionlen = length - namelen;
	logd("Custom Section: %s %i\n", name, sectionlen);
	if(strcmp(name, ".debug_line") == 0){
	  u8 * buffer = alloc0(sectionlen);
	  reader_read(rd, buffer, sectionlen);
	  module.dwarf_debug_lines = buffer;
	  module.dwarf_debug_lines_size = sectionlen;
	}else{
	  reader_advance(rd,length - namelen);
	}
	continue;
      }

    case WASM_TYPE_SECTION:
      {

	u32 length = reader_readu32(rd);
	logd("WASM TYPE SECTION %i\n", length);
	u32 typecount = reader_readu32(rd);
	module.type_count = typecount;
	module.types = alloc0(sizeof(module.types[0]) * module.type_count);
	for(u32 typeidx = 0; typeidx < typecount; typeidx++){
	
	  u8 header = reader_read1(rd);
	  ASSERT(header == 0x60);
	  u32 paramcount = reader_readu32(rd);
	  for(u32 i = 0; i < paramcount; i++){
	    reader_read1(rd); // discard
	  }

	  u32 returncount = reader_readu32(rd);
	  for(u32 i = 0; i < returncount; i++){
	    reader_read1(rd); // discard
	  }
	  module.types[typeidx].argcount = paramcount;
	  module.types[typeidx].retcount = returncount;
	}
	break;
      }
    case WASM_IMPORT_SECTION:
      {

	u32 length = reader_readu32(rd);
	logd("IMPORT SECTION %i\n", length);
	u32 guard = reader_getloc(rd);
	u32 importCount = reader_readu32(rd);
	logd("Import count: %i\n", importCount);
	for(u32 i = 0; i < importCount; i++){
	  char * modulename = reader_readname(rd);
	  char * name = reader_readname(rd);
	  wasm_import_type itype = reader_read1(rd);
	  switch(itype){
	  case WASM_IMPORT_FUNC:
	    {

	      u32 typeindex = reader_readu32(rd);
	      logd("IMPORT FUNC: %s %s %i\n", modulename, name, typeindex);
	      // imported funcs comes before defined ones.
	      wasm_module_add_func(&module);
	      wasm_function * f = module.func + module.import_func_count;
	      module.import_func_count += 1;

	      f->name = name;
	      f->functype = WASM_FUNCTION_TYPE_IMPORT;
	      f->type = typeindex;
	      f->module = modulename;
	      break;
	    }
	  case WASM_IMPORT_TABLE:
	    {
	      u8 elemtype = reader_read1(rd);
	      ASSERT(elemtype == 0x70);
	      u8 limitt = reader_read1(rd);
	      u32 min = 0, max = 0;
	      if(limitt == 0){
		min = reader_readu32(rd);
	      }else{
		min = reader_readu32(rd);
		max = reader_readu32(rd);
	      }
	      logd("TABLE: %i %i\n", min, max, elemtype);
	      module.import_table = alloc0(min * sizeof(module.import_table[0]));
	      module.import_table_count = min;
	    }
	    break;
	  case WASM_IMPORT_MEM:
	    {
	      u8 hasMax = reader_read1(rd);
	      u32 min = reader_readu32(rd), max = 0;
	    
	      if(hasMax){
		max = reader_readu32(rd);
	      }
	      
	      logd("IMPORT MEMORY: %i %i %i\n", hasMax, min, max);
	      wasm_heap_min_capacity(module.heap, min * WASM_PAGE_SIZE);
	      break;
	    }
	  case WASM_IMPORT_GLOBAL:
	    {
	      wasm_type type = (wasm_type) reader_read1(rd);
	      bool mut = reader_read1(rd);
	      const char * state  = mut ? "mutable" : "const";
	      ERROR("IMPORT GLOBAL: %s %s %i %i\n", module, name, state , type);
	      break;
	    }
	  }
	}
	if(guard + length != reader_getloc(rd))
	  ERROR("Parse imbalance %i != %i + %i (%x)!\n", reader_getloc(rd), guard, length);
	break;
      }
      case WASM_FUNCTION_SECTION:
      {
	logd("FUNCTION SECTION\n");
	u32 length = reader_readu32(rd);
	logd("Function section: length: %i\n", length);
	u32 guard = reader_getloc(rd);
	u32 funccount = reader_readu32(rd);
	logd("count: %i\n", funccount);
       
	for(u32 i = 0; i < funccount; i++){
	  u32 funcindex = module.import_func_count + i;
	  u32 f = reader_readu32(rd);
	  logd("Func %i: %i %i\n",i, f, funcindex);
	  if(module.func_count <= funcindex)
	    wasm_module_add_func(&module);
	  module.func[funcindex].type = f;
	  module.func[funcindex].argcount = module.types[f].argcount;
	  module.func[funcindex].retcount = module.types[f].retcount;
	}
	if(guard + length != reader_getloc(rd))
	  ERROR("Parse imbalance!\n");
	break;
      }
    case WASM_TABLE_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("TABLE SECTION (unsupported) %i\n", length);
	//table section is not needed as it is dynamically expanded later...
	reader_advance(rd, length);
      }
      break;
    case WASM_MEMORY_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("MEMORY SECTION (unsupported) %i\n", length);
	i32 memcount = reader_readu32(rd);
	ASSERT(memcount == 1);
	for(int i = 0; i < memcount; i++){
	  u8 type = reader_read1(rd);
	  u32 min = reader_readu32(rd);
	  wasm_heap_min_capacity(module.heap, min * WASM_PAGE_SIZE);
	  if(type == 0){

	    logd("Memory of %i pages\n", min);
	  }else if(type == 1){
	    u32 max = reader_readu32(rd);
	    logd("Memory of %i-%i pages (%i - %i)\n", min, max, min * WASM_PAGE_SIZE, max * WASM_PAGE_SIZE);
	  }else{
	    ERROR("Unsupported operation\n");
	  }
	}
      }
      break;
    case WASM_GLOBAL_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("GLOBAL section: length: %i\n", length);
	u32 global_count = reader_readu32(rd);
	module.globals = alloc0(sizeof(module.globals[0]) * global_count);
	module.global_count = global_count;
	for(u32 i = 0; i < global_count; i++){
	  u8 valtype = reader_read1(rd);
	  u8 mut = reader_read1(rd);
	  logd("GLOBAL %i: %x %s\n", i,  valtype, mut ? "MUT" : "CONST");
	  wasm_instr instr = reader_read1(rd);
	  switch(instr){
	  case WASM_INSTR_I32_CONST:
	    module.globals[i] = (u64)reader_readi32(rd);
	    break;
	  case WASM_INSTR_I64_CONST:
	    module.globals[i] = (u64)reader_readi64(rd);
	    break;
	  case WASM_INSTR_F32_CONST:
	    ((f64 *)module.globals)[i] = (f64) reader_readf64(rd);
	    break;
	  case WASM_INSTR_F64_CONST:
	    ((f64 *)module.globals)[i] = (f64) reader_readf64(rd);
	    break;
	  default:
	    ERROR("Unsupported Const type: %i\n", instr);
	  }
	  
	  wasm_instr end = reader_read1(rd);
	  ASSERT(end == WASM_INSTR_END); 
	}
      }
      break;
    case WASM_EXPORT_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("EXPORT section: length: %i\n", length);
	u32 exportcount = reader_readu32(rd);
	for(u32 i = 0; i < exportcount; i++){
	  char * name = reader_readname(rd);
	  wasm_import_type etype = (wasm_import_type) reader_read1(rd);
	  switch(etype){
	  case WASM_IMPORT_FUNC:
	    {
	      u32 index = reader_readu32(rd);

	      size_t local_func_index = module.local_func_count;
	      module.local_func_count += 1;
	      logd("EXPORT %s %i %i\n", name, index, local_func_index + module.import_func_count);
	      wasm_module_add_func(&module);
	      module.func[index].name = name;
	      break;
	    }
	  case WASM_IMPORT_TABLE:
	    {
	      ERROR("Not supported");
	      break;
	    }
	  case WASM_IMPORT_MEM:
	    {
	      u32 memory_index = reader_readu32(rd);
	      logd("MEMORY %i\n", memory_index);
	      break;
	    }
	  case WASM_IMPORT_GLOBAL:
	    {
	      u32 global_index = reader_readu32(rd);
	      logd("GLOBAL %i\n", global_index);
	      break;			 
	    }
	  }
	}
	break;
      }
    
    case WASM_START_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("START SECTION (unsupported) %i\n", length);
	reader_advance(rd, length);
      }break;
    case WASM_ELEMENT_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("Element section: length: %i\n", length);
	u32 elem_count = reader_readu32(rd);
	for(u32 i = 0; i < elem_count; i++){
	  u32 table_index = reader_readu32(rd);
	  ASSERT(table_index == 0);
	  wasm_instr instr = reader_read1(rd);
	  ASSERT(instr == WASM_INSTR_I32_CONST);

	  u32 offset = reader_readu32(rd);
	  wasm_instr end = reader_read1(rd);
	  ASSERT(end == WASM_INSTR_END);
	  u32 func_count = reader_readu32(rd);
	  if(module.import_table_count < func_count){
	    module.import_table = realloc(module.import_table, sizeof(module.import_table[0]) * (module.import_table_count = (1 + func_count)));
	  }
	  for(u32 i = 0; i < func_count; i++){
	    u32 idx = reader_readu32(rd);
	    logd("Function %i %i %i\n", func_count, offset, idx);
	    module.import_table[i + 1] = idx;
	  }
	}
      }
      break;
    case WASM_CODE_SECTION:
      {
	u32 code_section_offset = rd->offset;
	u32 length = reader_readu32(rd);
	logd("Code section: length: %i\n", length);
	u32 guard = reader_getloc(rd);
	u32 funccount = reader_readu32(rd);
	logd("Code Count: %i\n", funccount);
	for(u32 i = 0; i < funccount; i++){
	  int funcindex = i + module.import_func_count;

	  
	  u32 codesize = reader_readu32(rd);
	  u32 code_function_offset = rd->offset;
	  module.func[funcindex].code = rd->data + rd->offset;
	  module.func[funcindex].length = codesize;
	  module.func[funcindex].code_offset = code_function_offset - code_section_offset;

	  reader_advance(rd, codesize);
	}

	if(guard + length != reader_getloc(rd))
	  ERROR("Parse imbalance! %i %i %i\n", guard, length, reader_getloc(rd));
      }
      break;
    case WASM_DATA_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("Data Section: %i\n", length);
	u32 guard = reader_getloc(rd);
	u32 datacount = reader_readu32(rd);
	bool isGlobal = false;
	for(u32 i = 0; i < datacount; i++){
	  u32 memidx = reader_readu32(rd);
	  ASSERT(memidx == 0);
	  u32 offset = 0;

	  while(true){
	    wasm_instr instr = (wasm_instr)reader_read1(rd);
	    switch(instr){
	    case WASM_INSTR_I32_CONST:
	      {
		i32 _offset = reader_readi32(rd);
		offset = _offset;
		break;
	      }
	    case WASM_INSTR_GLOBAL_GET:
	      {
		i32 _offset = reader_readi32(rd);
		offset = _offset;
		isGlobal = true;
		break;
	      }
	    case WASM_INSTR_END:
	      goto end_read;
	      break;
	    default:
	      ERROR("UNSUPPORTED Instruction 0x%X", instr);
	    }
	  }
	end_read:;

	  u32 bytecount = reader_readu32(rd);
	  logd("DATA SECTION: %i %i %s\n", offset, bytecount, isGlobal ? "global" : "local");
	  wasm_heap_min_capacity(module.heap, bytecount + offset + 1);
	  reader_read(rd, module.heap->heap + offset, bytecount);
	}
	if(guard + length != reader_getloc(rd))
	  ERROR("Parse imbalance!\n");
	
      break;
      }
     default:
       {
	 u32 length = reader_readu32(rd);
	 logd("unsupported section%i, 0x%X\n", section, length);

	 reader_advance(rd, length);
       }  
    }
  }
  
  return mem_clone(&module, sizeof(module));
}

void wasm_execution_stack_keep_alive(wasm_execution_stack * trd, bool keep_alive){
  trd->keep_alive = keep_alive;
}


void wasm_module_add_stack(wasm_module * module, wasm_execution_stack * stk){
  stk->module = module;
  for(u32 i = 0; i < module->stack_count; i++){
    if(module->stacks[i] == NULL){
      module->stacks[i] = stk;
      return;
    }
  }
  module->stack_count += 1;
  
  module->stacks = realloc(module->stacks, sizeof(module->stacks[0]) * module->stack_count);

  module->stacks[module->stack_count - 1] = stk;

}

void wasm_module_remove_stack(wasm_module * module, wasm_execution_stack * ctx){
  for(u32 i = 0; i < module->stack_count; i++){
    if(module->stacks[i] == ctx)
      module->stacks[i] = NULL;
  }
}

static void wasm_stack_drop(wasm_execution_stack * ctx){
  ASSERT(ctx->stack_ptr > 0);
  logd("STACK DROP %i\n", ctx->stack_ptr);
  ctx->stack_ptr -= 1;
}

static void * wasm_stack_next(wasm_execution_stack * ctx){
  ctx->stack_ptr += 1;
  if(ctx->stack_ptr > ctx->stack_capacity){
    // ok to be a bit conservative wrt stack growing.
    ctx->stack = realloc(ctx->stack, sizeof(ctx->stack[0]) * (ctx->stack_capacity = (ctx->stack_ptr + 1) * 1.5));
    logd("increasing stack capacity to %i\n", ctx->stack_capacity);
  }

  return &ctx->stack[ctx->stack_ptr - 1];
}

static void wasm_push_data(wasm_execution_stack * ctx, void * data, size_t size){
  ASSERT(size <= 8);
  void * s = wasm_stack_next(ctx);
  u64 towrite = 0;
  memcpy(&towrite, data, size);
  memcpy(s, &towrite, sizeof(towrite));
}

static void wasm_push_i32(wasm_execution_stack * ctx, i32 v){
  i32 * s = wasm_stack_next(ctx);
  s[0] = v;
  s[1] = 0;
}

static void wasm_push_u32(wasm_execution_stack * ctx, u32 v){
  u32 * s = wasm_stack_next(ctx);
  s[0] = v;
  s[1] = 0;
}

static void wasm_push_u64(wasm_execution_stack * ctx, u64 v){
  u64 * s = wasm_stack_next(ctx);
  s[0] = v;
}

static void wasm_push_i64(wasm_execution_stack * ctx, i64 v){
  i64 * s = wasm_stack_next(ctx);
  s[0] = v;
}

static void wasm_push_f32(wasm_execution_stack * ctx, f32 v){
  f32 * s = wasm_stack_next(ctx);
  s[0] = v;
  s[1] = 0;
}

static void wasm_push_f64(wasm_execution_stack * ctx, f64 v){
  f64 * s = wasm_stack_next(ctx);
  s[0] = v;
}

static void wasm_pop_data(wasm_execution_stack * ctx, void * out){

  ASSERT(ctx->stack_ptr > 0);
  ctx->stack_ptr -= 1;
  memcpy(out, ctx->stack + ctx->stack_ptr, 8);
  logd("POP %i %p\n", ctx->stack_ptr, ((u64 *) out)[0]);
}

static void wasm_pop_data_2(wasm_execution_stack * ctx, void * out){
  logd("POP2 %i %p %p\n", ctx->stack_ptr, ctx->stack[ctx->stack_ptr- 1],ctx->stack[ctx->stack_ptr- 2] );
  ASSERT(ctx->stack_ptr > 1);
  ctx->stack_ptr -= 2;
  memcpy(out, ctx->stack + ctx->stack_ptr, 8 * 2);
}

static void * wasm_stack_pop(wasm_execution_stack * ctx){
  ctx->stack_ptr -= 1;
  return &ctx->stack[ctx->stack_ptr];
}

static void wasm_pop_i32(wasm_execution_stack * ctx, i32 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = (i32)val;
}

static void wasm_pop_i32_2(wasm_execution_stack * ctx, i32 * out, i32 * out2){
  i64 val[2];
  wasm_pop_data_2(ctx, val);
  *out = (i32)(val[1]);
  *out2 = (i32)(val[0]);
}

static void wasm_pop_u32(wasm_execution_stack * ctx, u32 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = (u32)val;
}

static void wasm_pop_u32_2(wasm_execution_stack * ctx, u32 * out, u32 * out2){
  u64 val[2];
  wasm_pop_data_2(ctx, val);
  *out = (u32)val[1];
  *out2 = (u32)val[0];
}

static void wasm_pop_i64(wasm_execution_stack * ctx, i64 * out){
  i64 * val = wasm_stack_pop(ctx);
  *out = val[0];
}

static void wasm_pop_i64_2(wasm_execution_stack * ctx, i64 * out, i64 * out2){
  i64 * val1 = wasm_stack_pop(ctx);
  i64 * val2 = wasm_stack_pop(ctx);
  *out = val1[0];
  *out2 = val2[0];
}

static void wasm_pop_u64(wasm_execution_stack * ctx, u64 * out){
  u64 * val = wasm_stack_pop(ctx);
  *out = val[0];
}

static void wasm_pop_u64_2(wasm_execution_stack * ctx, u64 * out, u64 * out2){
  u64 * val = wasm_stack_pop(ctx);
  *out = *val;
  val = wasm_stack_pop(ctx);
  *out2 = *val;
}

void wasm_pop2_i64(wasm_execution_stack * ctx, i64 * out){
  union{
    i64 val;
    struct{
      i32 x;
      i32 y;
    };
  }w;
  wasm_pop_i32(ctx, &w.y);
  wasm_pop_i32(ctx, &w.x);
  *out = w.val;
}

static void wasm_pop_f32(wasm_execution_stack * ctx, f32 *out){
  union{
    f32 o;
    u64 d;
  }w;
  wasm_pop_data(ctx, &w.d);
  *out = w.o;
}

static void wasm_pop_f32_2(wasm_execution_stack * ctx, f32 *out, f32 * out2){
  union{
    f32 o;
    u64 d;
  }w[2];
  wasm_pop_data_2(ctx, &w[0].d);
  *out = w[1].o;
  *out2 = w[0].o;
}

static void wasm_pop_f64(wasm_execution_stack * ctx, f64 * out){
  union{
    f64 o;
    u64 d;
  }w;
  wasm_pop_data(ctx, &w.d);
  *out = w.o;
}

static void wasm_pop_f64_2(wasm_execution_stack * ctx, f64 * out, f64 * out2){
  union{
    f64 o;
    u64 d;
  }w[2];
  wasm_pop_data_2(ctx, &w[0].d);
  *out = w[1].o;
  *out2 = w[0].o;
}

static void wasm_push_u64r(wasm_execution_stack * ctx, u64 * in){
  wasm_push_data(ctx, in, sizeof(in[0]));
}

static void load_op(wasm_code_reader * rd, wasm_execution_stack * ctx, int bytes){
  reader_readu32(rd); //align
  u32 offset = reader_readu32(rd);
  i32 addr;
  wasm_pop_i32(ctx, &addr);
  u32 total_offset = addr + offset;
  ASSERT(total_offset + bytes< ctx->module->heap->capacity);
  i64 * valptr = (ctx->module->heap->heap + total_offset);
  wasm_push_data(ctx, valptr, bytes);
}

static void store_op(wasm_code_reader * rd, wasm_execution_stack * ctx, int bytes){
  reader_readu32(rd); // align
  u32 offset = reader_readu32(rd);
  u64 value;
  wasm_pop_u64(ctx, &value);
  i32 addr;
  wasm_pop_i32(ctx, &addr);
  u32 total_offset = addr + offset;
  ASSERT(total_offset + bytes < ctx->module->heap->capacity);
  i64 * valptr = (ctx->module->heap->heap + total_offset );
  memcpy(valptr, &value, bytes);
}

static u64 * getlocal(wasm_execution_stack * ctx, u32 local){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  ASSERT(local < f->localcount);
  return ctx->stack + f->stack_pos + local;
}

static bool pop_label(wasm_execution_stack * ctx, bool move){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  if(f->block == 0){
    if(ctx->frame_ptr > 0){
      u64 return_value = 0;
      u32 localcount = f->localcount;
	
      if(localcount > 0){
	if(f->retcount == 1)
	  wasm_pop_u64(ctx, &return_value);

	logd("POP FRAME PTR %i\n", ctx->frame_ptr);
	for(u32 i = 0; i < localcount; i++)
	  wasm_stack_drop(ctx);
	if(f->retcount)
	  wasm_push_u64(ctx, return_value);
	
      }
      logd("dropped stack frame: frame stack pos: %i == stack ptr: %i ret count: %i\n", f->stack_pos, ctx->stack_ptr, f->retcount);
      if(f->stack_pos != ctx->stack_ptr - f->retcount){
	ERROR("Stack imbalance!");
      }
      ctx->frame_ptr -= 1;
      return true;
    }
    ERROR("UNEXPECTED END OF PROGRAM\n");
  }
  if(move){
    wasm_label * label = ctx->labels + f->label_offset + f->block - 1;
    if(label->offset){
      f->rd.offset = label->offset;
    }else{
      wasm_instr end = move_to_end_of_block(&f->rd, f->block);
      f->block -= 1; // skipping forward
      UNUSED(end);
    }
  }else{
    f->block -= 1; // skipping forward
  }
  return false;
}

static void pop_label2(wasm_execution_stack * ctx, int arity){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_label * label = ctx->labels + f->block + f->label_offset - (1 + arity);
  if(label->offset){
    f->rd.offset = label->offset;
    for(int i = 0; i < arity; i++){
      f->block -= 1; // skipping forward
    }
  }else{
    for(int i = 0; i < arity + 1; i++){
      wasm_instr end = move_to_end_of_block(&f->rd, f->block);
      f->block -= 1; // skipping forward
      UNUSED(end);
    }
  }
}

static void push_label(wasm_execution_stack * ctx, u8 blktype, bool forward){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  f->block += 1;
  int c = f->block + f->label_offset - ctx->label_capacity;
  if(c > 0){
    ctx->labels = realloc(ctx->labels, (ctx->label_capacity = ctx->label_capacity + c) * sizeof(ctx->labels[0]));
  }
  wasm_label * label = ctx->labels + f->label_offset + f->block - 1;
  label->type = blktype;
  label->offset = forward ? 0 : f->rd.offset;
}

static void return_from(wasm_execution_stack * ctx){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  while(f->block > 0){
    wasm_label * label = ctx->labels + f->block - 1;
    if(label->type != 0x40){
      wasm_stack_drop(ctx);
    }
    pop_label(ctx, false);
  }
  pop_label(ctx, false);
}

static bool push_stack_frame(wasm_execution_stack * ctx){
  bool changed;
  if(ctx->frame_ptr + 1 >= ctx->frame_capacity){
    ctx->frames = realloc(ctx->frames, sizeof(ctx->frames[0]) * (ctx->frame_capacity += 1));
    changed = true;
  }else{
    changed = false;
  }
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  u32 block = f->block + f->label_offset;
  ctx->frame_ptr += 1;
  f += 1;
  memset(f, 0, sizeof(ctx->frames[0]));
  f->label_offset = block;
  f->func_id = -1;
  return changed;
}

static i64 func_index(wasm_module * mod, const char * name){
  if(name == NULL) return -1;
  for(u64 i = 0; i < mod->func_count; i++){
    if(mod->func[i].name != NULL && strcmp(name, mod->func[i].name) == 0){
      return (i64)i;
    }
  }
  return -1;
}

bool wasm_stack_is_finalized(wasm_execution_stack * ctx){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_code_reader * rd = &f->rd;
  if(rd->offset == rd->size)
    return true;
  
  return false;
}


wasm_execution_stack * current_stack;
void standard_error_callback(const char * file, int line, const char * msg, ...){
  static char errorbuffer[100];
  UNUSED(file);
  UNUSED(line);
  va_list args;
  va_start (args, msg);
  int cnt = vsprintf (errorbuffer,msg, args);
  va_end (args);
  printf("Error: %s\n", errorbuffer);
  current_stack->error = (char *) mem_clone(errorbuffer, cnt + 1);
  current_stack->yield = true;
}


int wasm_exec_code2(wasm_execution_stack * ctx, int stepcount){
  current_stack = ctx;
  ctx->complex_state = ctx->yield || breakcheck_enabled(ctx);
  int startcount = stepcount;
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_code_reader * rd = &f->rd;
  wasm_module * mod = ctx->module;
  ASSERT(mod);
  while(rd->offset < rd->size && stepcount > 0){
    if(ctx->complex_state){
      if(ctx->yield) break;
      if(breakcheck_enabled(ctx))
	breakcheck_run(ctx);
    }

    stepcount--;
    wasm_instr instr = reader_read1(rd);
    logd("- %x: %s(%x) (/%x)\n", rd->offset, wasm_instr_name[instr], instr, stepcount);
    switch(instr){

    case WASM_INSTR_UNREACHABLE:
      ERROR("Unreachable code executed\n");
      logd("THIS HAPPEND\n");
      break;
    case WASM_INSTR_NOP:
      ERROR("NOP NOT SUPPORTED");
      break;
    case WASM_INSTR_BLOCK:
      {
	u8 blktype = reader_read1(rd);
	logd("block type: %i\n", blktype);
	push_label(ctx, blktype, true);
      }
      break;
    case WASM_INSTR_LOOP:
      {
	u8 blktype = reader_read1(rd);
	logd("block type: %i\n", blktype);
	push_label(ctx, blktype, false);
      }
      break;
    case WASM_INSTR_IF:
      {
	u8 blktype = reader_read1(rd);
	push_label(ctx, blktype, true);
	u64 cnd;
	wasm_pop_u64(ctx, &cnd);
	if(cnd){
	  logd("ENTER IF %x %p\n", reader_read1(rd), cnd);
	  rd->offset -= 1;
	}else{
	  logd("ENTER ELSE\n");	
	  wasm_instr end = move_to_end_of_block(rd, f->block);
	  switch(end){
	  case WASM_INSTR_ELSE:
	    logd("Found ELSE!!\n");
	    break;
	  case WASM_INSTR_END:
	    // this happens
	    logd("Found END!!\n");
	    ASSERT(pop_label(ctx, false) == false);
	    break;
	  default:
	    ERROR("Should not happen\n");
	  }
	}
	break;

      }
    case WASM_INSTR_ELSE: 
      {
	// this can only happens during an 'if'.
	logd("SKIP ELSE\n");
	wasm_instr end = move_to_end_of_block(rd, f->block);

	switch(end){
	case WASM_INSTR_END:
	  ASSERT(pop_label(ctx, false) == false);
	  break;
	default:
	  ERROR("Unsupported instruction: %x\n", end);
	}
      }
      break;
    case WASM_INSTR_END:
      logd("END %i %i\n", ctx->frame_ptr, stepcount);
      if(pop_label(ctx, false)){

	f = ctx->frames + ctx->frame_ptr;
	rd = &f->rd;
      }

      break;
    case WASM_INSTR_BR:
      {

      wasm_instr_br:;

	u32 brindex = reader_readu32(rd);
	logd("BR %i\n", brindex);
	pop_label2(ctx, brindex);
      }
      break;
    case WASM_INSTR_BR_IF:
      {

	u32 x;
	wasm_pop_u32(ctx, &x);
	logd("BR IF %x %i\n", x, f->block);
	if(x)
	  goto wasm_instr_br;
	reader_readu32(rd);
	//else continue..
      }
      break;
    case WASM_INSTR_BR_TABLE:
      {
	u32 x;
	wasm_pop_u32(ctx, &x);	
	u32 cnt = reader_readu32(rd);
	u32 items[cnt];
	for(u32 i = 0; i < cnt; i++){
	  items[i] = reader_readu32(rd);
	}
	u32 ret = reader_readu32(rd);
	u32 brindex;
	if(x < cnt)
	  brindex = items[x];
	else
	  brindex = ret;
	logd("br table: arg: %i  idx:%i\n", x, brindex);
	pop_label2(ctx, brindex);	
      }
      break;
    case WASM_INSTR_RETURN:
      {
	return_from(ctx);
	f = ctx->frames + ctx->frame_ptr;
	rd = &f->rd;
      }
      break;
    case WASM_INSTR_CALL:
    case WASM_INSTR_CALL_INDIRECT:
      {
	u32 fcn;
	if(instr == WASM_INSTR_CALL_INDIRECT){
	  u32 typeidx = reader_readu32(rd);
	  UNUSED(typeidx);
	  ASSERT(reader_read1(rd) == 0);
	  wasm_pop_u32(ctx, &fcn);
	  if(fcn >= mod->import_table_count){
	    ERROR("Invalid indirect call: %i %i\n", fcn, mod->import_table_count);
	  }
	  fcn = mod->import_table[fcn];
	}else{
	  fcn = reader_readu32(rd);
	}
	if(fcn > mod->func_count){
	  ERROR("Unknown function %i\n", fcn);
	}
	wasm_function * fn = mod->func + fcn;
	if(fn->functype == WASM_FUNCTION_TYPE_IMPORT){
	  logd("CALLf %s (%i)\n",fn->name, fcn);
	  void (* fcn)(wasm_execution_stack * stack) = fn->code;
	  if(fcn == NULL){
	    ERROR("Unlinked symbol: %s\n", fn->name);
	  }
	  fcn(ctx);
	  if(ctx->yield){
	    ctx->yield = false;
	    return startcount - stepcount;
	  }
	}else{

	  logd("CALL %s (%i)\n",fn->name, fcn);
	  push_stack_frame(ctx);
	  f = ctx->frames + ctx->frame_ptr;
	  rd = &f->rd;
	  f->retcount = fn->retcount;
	  f->stack_pos = ctx->stack_ptr - fn->argcount;
	  f->func_id = fcn;
	  //f->argcount = fn->argcount;
	  rd[0] = (wasm_code_reader){.data = fn->code, .size = fn->length, .offset = 0};
	  u32 l = reader_readu32(rd);
	  for(u32 i = 0; i < l; i++){
	    u32 elemcount = reader_readu32(rd);
	    u8 type = reader_read1(rd);

	    { // sanity check
	      switch(type){
	      case WASM_TYPE_F64:
	      case WASM_TYPE_F32:
	      case WASM_TYPE_I32:
	      case WASM_TYPE_I64:
		break;
	      default:
		ERROR("Unsupported type\n");
	      }
	    }
	    for(u32 i = 0; i < elemcount; i++){
	      wasm_push_u64(ctx, 0);
	    }
	    f->localcount += elemcount;
	  }
	  f->localcount += fn->argcount;
	}
      }
      break;
    case WASM_INSTR_DROP:
      wasm_stack_drop(ctx);
      break;

    case WASM_INSTR_SELECT:
      {
	u64 x,y,s;
	wasm_pop_u64(ctx, &s);
	wasm_pop_u64(ctx, &y);
	wasm_pop_u64(ctx, &x);

	u64 result = (s != 0) ? x : y;
	logd("SELECT %i %i %p: %i\n", x, y, s, result);
	wasm_push_u64(ctx, result);
      }
      break;
      
    case WASM_INSTR_LOCAL_SET:
      {
	u32 local = reader_readu32(rd);
	u64 * localptr = getlocal(ctx, local);
	wasm_pop_u64(ctx, localptr);
	logd("Local set %i: %p\n", local, localptr[0]);
	break;
      }
    case WASM_INSTR_LOCAL_GET:
      {
	u32 local = reader_readu32(rd);
	u64 val = getlocal(ctx, local)[0];
	wasm_push_u64(ctx, val);
	logd("Local get %i: %p %f\n", local, val, val);
      }
      break;
    case WASM_INSTR_LOCAL_TEE:
      {
	u32 local = reader_readu32(rd);
	u64 value;
	wasm_pop_u64(ctx, &value);
	wasm_push_u64(ctx, value);	
	getlocal(ctx, local)[0] = value;
	logd("Set local %i to %i\n", local, value);
      }
      break;
    case WASM_INSTR_GLOBAL_SET:
      {
	u32 global_index = reader_readu32(rd);
	wasm_pop_u64(ctx, mod->globals + global_index);
	break;
      }
    case WASM_INSTR_GLOBAL_GET:
      {
	u32 global_index = reader_readu32(rd);
	wasm_push_u64r(ctx, mod->globals + global_index);
	break;
      }
    case WASM_INSTR_I32_LOAD:
      load_op(rd, ctx, 4); break;
    case WASM_INSTR_I64_LOAD:
      load_op(rd, ctx, 8); break;
    case WASM_INSTR_F32_LOAD:
      load_op(rd, ctx, 4); break;
    case WASM_INSTR_F64_LOAD:
      load_op(rd, ctx, 8); break;
    case WASM_INSTR_I32_LOAD8_S: // 0x2C,
      load_op(rd, ctx, 1);break;
    case WASM_INSTR_I32_LOAD8_U: // 0x2D,
      load_op(rd, ctx, 1);break;
    case WASM_INSTR_I32_LOAD16_S: // 0x2E,
      load_op(rd, ctx, 2);break;
    case WASM_INSTR_I32_LOAD16_U: // 0x2F,
      load_op(rd, ctx, 2);break;
    case WASM_INSTR_I64_LOAD8_S: // 0x30,
      load_op(rd, ctx, 1);break;
    case WASM_INSTR_I64_LOAD8_U: // 0x31,
      load_op(rd, ctx, 1);break;
    case WASM_INSTR_I64_LOAD16_S: // 0x32,
      load_op(rd, ctx, 2);break;
    case WASM_INSTR_I64_LOAD16_U: // 0x33,
      load_op(rd, ctx, 2);break;
    case WASM_INSTR_I64_LOAD32_S: // 0x34,
      load_op(rd, ctx, 4);break;
    case WASM_INSTR_I64_LOAD32_U: // 0x35,
      load_op(rd, ctx, 4);break;
      
    case WASM_INSTR_I32_STORE: // 0x36,
      store_op(rd, ctx, 4);break;
    case WASM_INSTR_I64_STORE: // 0x37,
      store_op(rd, ctx, 8);break;
    case WASM_INSTR_F32_STORE: // 0x38,
      store_op(rd, ctx, 4);break;
    case WASM_INSTR_F64_STORE: // 0x39,
      store_op(rd, ctx, 8);break;
    case WASM_INSTR_I32_STORE_8: // 0x3A,
      store_op(rd, ctx, 1);break;
    case WASM_INSTR_I32_STORE_16: // 0x3B,
      store_op(rd, ctx, 2);break;
    case WASM_INSTR_I64_STORE_8: // 0x3C,
      store_op(rd, ctx, 1);break;
    case WASM_INSTR_I64_STORE_16: // 0x3D,
      store_op(rd, ctx, 2);break;
    case WASM_INSTR_I64_STORE_32: // 0x3E,
      store_op(rd, ctx, 4);break;
    case WASM_INSTR_MEMORY_SIZE: // = 0x3F,
      {
	reader_read1(rd);
	size_t cap = mod->heap->capacity;
	wasm_push_u64(ctx, cap / WASM_PAGE_SIZE);
	logd("MEMORY SIZE: %i\n", cap);
      }
      break;
    case WASM_INSTR_MEMORY_GROW:// = 0x40,
      {
	ERROR("Not supported!\n");
	u32 newsize = 0;
	wasm_pop_u32(ctx, &newsize);
	newsize = newsize;
	wasm_heap_min_capacity(mod->heap, newsize * WASM_PAGE_SIZE);
	wasm_push_u32(ctx, newsize);
	logd("MEMORY GROW: New memory size: %p\n", newsize);
      }
      break;
    case WASM_INSTR_I32_CONST:
      wasm_push_i32(ctx, reader_readi32(rd)); break;
    case WASM_INSTR_I64_CONST:
      {
	i64 v = reader_readi64(rd);
	logd("Const value %p\n", v);
	wasm_push_i64(ctx, v);
	break;
      }
    case WASM_INSTR_F32_CONST:
      wasm_push_f32(ctx, reader_readf32(rd)); break;
    case WASM_INSTR_F64_CONST:
      wasm_push_f64(ctx, reader_readf64(rd)); break;
    case WASM_INSTR_I32_EQZ:
      UNARY_OPF(i32, OP_EQZ);
    case WASM_INSTR_I32_EQ:
      BINARY_OP(i32, ==);
    case WASM_INSTR_I32_NE:
      BINARY_OP(i32, !=);
    case WASM_INSTR_I32_LT_S:
      BINARY_OP(i32, <);
    case WASM_INSTR_I32_LT_U:
      BINARY_OP(u32, <);
    case WASM_INSTR_I32_GT_S:
      BINARY_OP(i32, >);
    case WASM_INSTR_I32_GT_U:
      BINARY_OP(u32, >);
    case WASM_INSTR_I32_LE_S: // 0x4C,
      BINARY_OP(i32, <);
    case WASM_INSTR_I32_LE_U: // 0x4D,
      BINARY_OP(u32, <);
    case WASM_INSTR_I32_GE_S:
      BINARY_OP(i32, >=);
    case WASM_INSTR_I32_GE_U:
      BINARY_OP(u32, >=);

    case WASM_INSTR_I64_EQ:
      BINARY_OP(i64, ==);
    case WASM_INSTR_I64_NE:
      BINARY_OP(i64, !=);
    case WASM_INSTR_I64_LT_S:
      BINARY_OP(i64, <);
    case WASM_INSTR_I64_LT_U:
      BINARY_OP(u64, <);
    case WASM_INSTR_I64_GT_S:
      BINARY_OP(i64, >);
    case WASM_INSTR_I64_GT_U:
      BINARY_OP(u64, >);
    case WASM_INSTR_I64_LE_S: // 0x57,
      BINARY_OP(i32, <);
    case WASM_INSTR_I64_LE_U: // 0x58,
      BINARY_OP(u32, <);
    case WASM_INSTR_I64_GE_S:
      BINARY_OP(i64, >=);
    case WASM_INSTR_I64_GE_U:
      BINARY_OP(u64, >=);

    case WASM_INSTR_F32_EQ:
      BINARY_OP_U64(f32, ==);
    case WASM_INSTR_F32_NE:
      BINARY_OP_U64(f32, !=);
    case WASM_INSTR_F32_LT:
      BINARY_OP_U64(f32, <);
    case WASM_INSTR_F32_GT:
      BINARY_OP_U64(f32, >);
    case WASM_INSTR_F32_LE:
      BINARY_OP_U64(f32, <=);
    case WASM_INSTR_F32_GE:
      BINARY_OP_U64(f32, <=);
    case WASM_INSTR_F64_EQ:
      BINARY_OP_U64(f64, ==);
    case WASM_INSTR_F64_NE:
      BINARY_OP_U64(f64, !=);
    case WASM_INSTR_F64_LT:
      BINARY_OP_U64(f64, <);
    case WASM_INSTR_F64_GT:
      BINARY_OP_U64(f64, >);
    case WASM_INSTR_F64_LE:
      BINARY_OP_U64(f64, <=);
    case WASM_INSTR_F64_GE:
      BINARY_OP_U64(f64, <=);
      
    case WASM_INSTR_I32_ADD:
      BINARY_OP(i32, +);
    case WASM_INSTR_I32_SUB:
      BINARY_OP(i32, -);
    case WASM_INSTR_I32_MUL:
      BINARY_OP(i32, *);
    case WASM_INSTR_I32_DIV_S:
      BINARY_OP(i32, /);
    case WASM_INSTR_I32_DIV_U:
      BINARY_OP(u32, /);
    case WASM_INSTR_I32_REM_S:
      BINARY_OP(i32, %);
    case WASM_INSTR_I32_REM_U:
      BINARY_OP(u32, %);
    case WASM_INSTR_I32_AND:
      BINARY_OP(i32, &);
    case WASM_INSTR_I32_OR:
      BINARY_OP(i32, |);
    case WASM_INSTR_I32_XOR:
      BINARY_OP(i32, ^);
    case WASM_INSTR_I32_SHL:
      BINARY_OP(i32, <<);
    case WASM_INSTR_I32_SHR_S:
      BINARY_OP(i32, >>);
    case WASM_INSTR_I32_SHR_U:
      BINARY_OP(u32, >>);
    case WASM_INSTR_I64_CLZ:// = 0x79,
      UNSUPPORTED_OP(CLZ);
    case WASM_INSTR_I64_CTZ:// = 0x7A,
      UNSUPPORTED_OP(CTZ);
    case WASM_INSTR_I64_POPCNT:// 0x7B,
      UNSUPPORTED_OP(POPCNT);
    case WASM_INSTR_I64_ADD:// 0x7C,
      BINARY_OP(i64, +);
    case WASM_INSTR_I64_SUB:// 0x7D,
      BINARY_OP(i64, -);
    case WASM_INSTR_I64_MUL:// 0x7E,
      BINARY_OP(i64, *);
    case WASM_INSTR_I64_DIV_S:// 0x7F,
      BINARY_OP(i64, /);
    case WASM_INSTR_I64_DIV_U:// 0x80,
      BINARY_OP(u64, /);
    case WASM_INSTR_I64_REM_S:// 0x81,
      BINARY_OP(i64, %);
    case WASM_INSTR_I64_REM_U:// 0x82,
      BINARY_OP(u64, %);
    case WASM_INSTR_I64_AND:// 0x83,
      BINARY_OP(i64, &);
    case WASM_INSTR_I64_OR:// 0x84,
      BINARY_OP(i64, |);
    case WASM_INSTR_I64_XOR:// 0x85,
      BINARY_OP(i64, ^);
    case WASM_INSTR_I64_SHL:// 0x86,
      BINARY_OP(i64, <<);
    case WASM_INSTR_I64_SHR_S:// 0x87,
      BINARY_OP(i64, >>);
    case WASM_INSTR_I64_SHR_U:// 0x88,
      BINARY_OP(u64, >>);
    case WASM_INSTR_I64_ROTL:// 0x89,
      UNSUPPORTED_OP(ROTL);
    case WASM_INSTR_I64_ROTR:// 0x9A,
      UNSUPPORTED_OP(ROTR);

    case WASM_INSTR_F32_ABS: //0x8B,
      UNARY_OPF(f32, fabs);
    case WASM_INSTR_F32_NEG: //0x8C,
      UNARY_OPF(f32, OP_NEG);
    case WASM_INSTR_F32_CEIL: //0x8D,
      UNARY_OPF(f32, ceil);
    case WASM_INSTR_F32_FLOOR: //0x8E,
      UNARY_OPF(f32, floor);
    case WASM_INSTR_F32_TRUNC: //0x8F,
      UNARY_OPF(f32, trunc);
    case WASM_INSTR_F32_NEAREST: //0x90,
      UNARY_OPF(f32, round);
    case WASM_INSTR_F32_SQRT: //0x91,
      UNARY_OPF(f32, sqrtf);   
    case WASM_INSTR_F32_ADD: //0x92,
      BINARY_OP(f32, +);
    case WASM_INSTR_F32_SUB: //0x93,
      BINARY_OP(f32, -);
    case WASM_INSTR_F32_MUL: //0x94,
      BINARY_OP(f32, *);
    case WASM_INSTR_F32_DIV: //0x95,
      BINARY_OP(f32, /);
    case WASM_INSTR_F32_MIN: //0x96,
      BINARY_OPF(f32, MIN);
    case WASM_INSTR_F32_MAX: //0x97,
      BINARY_OPF(f32, MAX);
    case WASM_INSTR_F32_COPYSIGN: //0x98,
      UNARY_OPF(f32, SIGN);

    case WASM_INSTR_F64_ABS: //0x8B,
      UNARY_OPF(f64, abs);
    case WASM_INSTR_F64_NEG: //0x8C,
      UNARY_OPF(f64, OP_NEG);
    case WASM_INSTR_F64_CEIL: //0x8D,
      UNARY_OPF(f64, ceil);
    case WASM_INSTR_F64_FLOOR: //0x8E,
      UNARY_OPF(f64, floor);
    case WASM_INSTR_F64_TRUNC: //0x8F,
      UNARY_OPF(f64, trunc);
    case WASM_INSTR_F64_NEAREST: //0x90,
      UNARY_OPF(f64, round);
    case WASM_INSTR_F64_SQRT: //0x91
      UNARY_OPF(f64, sqrt);   
    case WASM_INSTR_F64_ADD: //0x92,
      BINARY_OP(f64, +);
    case WASM_INSTR_F64_SUB: //0x93,
      BINARY_OP(f64, -);
    case WASM_INSTR_F64_MUL: //0x94,
      BINARY_OP(f64, *);
    case WASM_INSTR_F64_DIV: //0x95,
      BINARY_OP(f64, /);
    case WASM_INSTR_F64_MIN: //0x96,
      BINARY_OPF(f64, MIN);
    case WASM_INSTR_F64_MAX: //0x97,
      BINARY_OPF(f64, MAX);
    case WASM_INSTR_F64_COPYSIGN: //0x98,
      UNARY_OPF(f64, SIGN);
    case WASM_INSTR_I32_WRAP_I64: // 0xA7
      CAST_OP(i64, i32);
    case WASM_INSTR_I32_TRUNC_F32_S: // 0xA8,
      UNARY_OPF(f32, TRUNCF_I32);
    case WASM_INSTR_I32_TRUNC_F32_U: // 0xA9,
      UNARY_OPF(f32, TRUNCF_U32);
    case WASM_INSTR_I32_TRUNC_F64_S: // 0xAA,
      UNARY_OPF(f64, TRUNCD_I32);
    case WASM_INSTR_I32_TRUNC_F64_U: // 0xAB,
      UNARY_OPF(f64, TRUNCD_U32);
    case WASM_INSTR_I64_EXTEND_I32_S: // 0xAC,
      UNARY_OPF(i32, EXTEND_I64_I32);
    case WASM_INSTR_I64_EXTEND_I32_U: // 0xAD,
      UNARY_OPF(u32, EXTEND_I64_U32);
    case WASM_INSTR_I64_TRUNC_F32_S: //0xAE,
      UNARY_OPF(f32, TRUNCF_I64);
    case WASM_INSTR_I64_TRUNC_F32_U: //0xAF,
      UNARY_OPF(f32, TRUNCF_U64);
    case WASM_INSTR_I64_TRUNC_F64_S: //0xB0,
      UNARY_OPF(f64, TRUNCD_I64);
    case WASM_INSTR_I64_TRUNC_F64_U: //0xB1,
      UNARY_OPF(f64, TRUNCD_U64);
    case WASM_INSTR_F32_CONVERT_I32_S: //0xB2,
      UNARY_OPF(f32, CONVERT_TO_F32);
    case WASM_INSTR_F32_CONVERT_I32_U: //0xB3,
      UNARY_OPF(f32, CONVERT_TO_F32);
    case WASM_INSTR_F32_CONVERT_I64_S: //0xB4,
      UNARY_OPF(f32, CONVERT_TO_F32);
    case WASM_INSTR_F32_CONVERT_I64_U: //0xB5,
      UNARY_OPF(f32, CONVERT_TO_F32);
    case WASM_INSTR_F32_DEMOTE_F64: //0xB6,
      CAST_OP(f64, f32);
    case WASM_INSTR_F64_CONVERT_I32_S: //0xB7,
      UNARY_OPF(f32, CONVERT_TO_F64);
    case WASM_INSTR_F64_CONVERT_I32_U: //0xB8,
      UNARY_OPF(f32, CONVERT_TO_F64);
    case WASM_INSTR_F64_CONVERT_I64_S: //0xB9,
      UNARY_OPF(f32, CONVERT_TO_F64);
    case WASM_INSTR_F64_CONVERT_I64_U: //0xBA,
      UNARY_OPF(f32, CONVERT_TO_F64);
    case WASM_INSTR_F64_PROMOTE_F32: //0xBB,
      CAST_OP(f32,f64);
    case WASM_INSTR_I32_REINTERPRET_F32: //0xBC,
      break; // bits are already on the stack
    case WASM_INSTR_I64_REINTERPRET_F64: //0xBD,
      break;
    case WASM_INSTR_F32_REINTERPRET_I32: //0xBE,
      break;
    case WASM_INSTR_F64_REINTERPRET_I64: //0xBF
      break;
    
    default:
      ERROR("Unknown opcode %x\n", instr);
      break;
    }
  }
  return startcount - stepcount;
}

void wasm_load_code(wasm_execution_stack * ctx, u8 * code, size_t l){
  ctx->frames = realloc(ctx->frames, sizeof(ctx->frames[0]));
  memset(ctx->frames, 0, sizeof(ctx->frames[0]));
  ctx->frame_capacity = 1;
  wasm_control_stack_frame * f = ctx->frames;
  f->rd.offset = 0;
  f->rd.size = l;
  f->rd.data = code;
  f->func_id = -1;
  ctx->frame_ptr = 0;
}

void wasm_fork_stack(wasm_execution_stack * init_ctx){
  wasm_execution_stack * ctx = mem_clone(init_ctx, sizeof(ctx[0]));
  ctx->stack_capacity = ctx->stack_ptr;
  wasm_module_add_stack(ctx->module, ctx);
  ctx->stack = mem_clone(ctx->stack, sizeof(ctx->stack[0]) * ctx->stack_capacity);
  ctx->frames = mem_clone(ctx->frames, sizeof(ctx->frames[0]) * ctx->frame_capacity);
  ctx->labels = mem_clone(ctx->labels, sizeof(ctx->labels[0]) * ctx->label_capacity);
  wasm_push_i32(ctx, 1);
  wasm_push_i32(init_ctx, 0);
  ctx->initializer = NULL; // no initialization was done here. Reset it to avoid double free.
  ctx->initializer_size = 0;
}

void wasm_delete_stack(wasm_execution_stack * stk){
  wasm_module_remove_stack(stk->module, stk);
  dealloc(stk->stack);
  dealloc(stk->frames);
  dealloc(stk->labels);
  if(stk->initializer != NULL)
    dealloc(stk->initializer);
  dealloc(stk);
  stk->initializer_size = 0;
}

int wasm_exec_code3(wasm_execution_stack * ctx, u8 * code, size_t l, u32 steps){
  wasm_load_code(ctx, code, l);
  return wasm_exec_code2(ctx, steps);
}

void awsm_register_function(wasm_module * module, void (* func)(wasm_execution_stack * stack), const char * name){
  
  for(u32 i = 0; i < module->import_func_count; i++){

    if(strcmp(module->func[i].name, name) == 0){

      wasm_function * f = module->func + i;
      f->functype = WASM_FUNCTION_TYPE_IMPORT;
      f->code = func;
      return;
    }
  }
  // overwrite local func. This is useful since the VM can provide prototype function definitions
  // and then overwrite them with an actual implementation.
  for(u32 _i = 0; _i < module->local_func_count; _i++){
    u32 i = module->import_func_count + _i;
    if(strcmp(module->func[i].name, name) == 0){
      
      wasm_function * f = module->func + i;
      f->functype = WASM_FUNCTION_TYPE_IMPORT;
      f->code = func;
      return;
    }
  }
}

int awsm_get_function(wasm_module * module, const char * name){
  return func_index(module, name);
}

int awsm_get_function_arg_cnt(wasm_module * module, int id){
  return module->func[id].argcount;
}
int awsm_get_function_ret_cnt(wasm_module * module, int id){
  return module->func[id].retcount;
}

int awsm_define_function(wasm_module * module, const char * name, void * code, size_t len, int retcount, int argcount){
  int j = awsm_get_function(module, name);
  bool exists = j != -1;
  if(j == -1)
    j = wasm_module_add_func(module);
  wasm_function * f = module->func + j;

  if(exists){
    dealloc(f->code);
  }else{
    f->name = mem_clone(name, strlen(name) + 1);
  }

  f->code = mem_clone(code, len);
  f->length = len;
  f->module = NULL;//module->name;
  f->retcount = retcount;
  f->argcount = argcount;
  return (int) j;
}

u64 awsm_new_global(wasm_module * module){
  u64 index = module->global_count;
  module->global_count += 1;
  module->globals = realloc(module->globals, sizeof(module->globals[0]) * module->global_count);
  return index;
}


typedef wasm_execution_stack stack;

void _print_i32(stack * ctx){
  i32 v;
  wasm_pop_i32(ctx, &v);
  log("%i", v);
}

void _print_i64(stack * ctx){
  i64 v;
  wasm_pop_i64(ctx, &v);
  log("%i\n", v);
}

void _print_str(stack * ctx){
  char * str = awsm_pop_ptr(ctx);
  i32 v2 = printf("%s", str);
  wasm_push_i32(ctx, v2);
}

void _print_f32(stack * ctx){
  f32 v;
  wasm_pop_f32(ctx, &v);
  log("%f", v);
}

void _print_f64(stack * ctx){
  f64 v;
  wasm_pop_f64(ctx, &v);
  log("%f", v);
}

void _require_f64(stack * ctx){
  f64 a, b;
  wasm_pop_f64(ctx, &a);
  wasm_pop_f64(ctx, &b);
  if(a != b) ERROR("Require: does not match\n");
}

void _require_f32(stack * ctx){
  f32 a, b;
  wasm_pop_f32(ctx, &a);
  wasm_pop_f32(ctx, &b);
  if(a != b) ERROR("Require: does not match\n");
}

void _require_i64(stack * ctx){
  i64 a, b;
  wasm_pop_i64(ctx, &a);
  wasm_pop_i64(ctx, &b);
  if(a != b)
    ERROR("Require: does not match\n");
}

void _require_i32(stack * ctx){
  i32 a, b;
  wasm_pop_i32(ctx, &a);
  wasm_pop_i32(ctx, &b);
  if(a != b)
    ERROR("Require: does not match\n");
}

void _sbrk(stack * ctx){
  ERROR("SBRK Not supported!");
  wasm_module * mod = ctx->module;
  i32 v;
  wasm_pop_i32(ctx, &v);
  logd("SBRK(%i)\n",v);
  wasm_push_u32(ctx,  mod->heap->capacity);
  if(v > 0)
    mod->heap->heap = realloc(mod->heap->heap, mod->heap->capacity += v);
}

void _wasm_error(stack * ctx){
  
  i32 v;
  wasm_pop_i32(ctx, &v);
  char * str = (ctx->module->heap->heap + v);
  ERROR("%s", str);
}

// u64 new_coroutine(void (* f)(void * arg), void * arg);

void _new_coroutine(stack * ctx){
  u64 val = awsm_pop_u64(ctx);
  u64 fcn = awsm_pop_u64(ctx);
  

  wasm_module * module = ctx->module;
  logd("coroutine: (%i) %s\n", fcn, module->func[fcn].name);

  awsm_push_u64(ctx, 0);

  stack * ctx2 = alloc0(sizeof(ctx[0]));
  wasm_module_add_stack(module, ctx2);
  awsm_push_u64(ctx, (u64) ctx2);

  i64 main_index = fcn;
  
  logd("Load... %i\n", main_index);

  u8 * code = alloc0(16);
  code[0] = WASM_INSTR_CALL_INDIRECT;
  //u32 len = encode_u64_leb((u64)fcn, code + 1);
  ctx2->initializer = code;
  ctx2->initializer_size = 16;

  wasm_push_u64(ctx2, val);
  wasm_push_u64(ctx2, fcn);
  wasm_load_code(ctx2, ctx2->initializer, 3);
}

void _yield(stack * ctx){
  ctx->yield = true;
}

void _get_heap_size(stack * ctx){
  i64 heap_capacity = (i64) ctx->module->heap->capacity;
  awsm_push_i64(ctx, heap_capacity);
}

void _set_heap_size(stack * ctx){
  i64 newcap = awsm_pop_i64(ctx);
  wasm_heap_min_capacity(ctx->module->heap, (size_t) newcap);
  
}

wasm_module * awsm_load_module_from_file(const char * wasm_file){
  size_t buffer_size = 0;
  void * data = read_file_to_buffer(wasm_file, &buffer_size);
  if(data == NULL){
    ERROR("awsm error: Cannot load file: %s", wasm_file);
    return NULL;
  }
  wasm_heap * heap = alloc0(sizeof(heap[0]));
  wasm_code_reader rd = {.data = data, .size = buffer_size, .offset = 0};
  wasm_module * mod = load_wasm_module(heap, &rd);
  awsm_register_function(mod, _print_i32, "print_i32");
  awsm_register_function(mod, _print_i64, "print_i64");
  awsm_register_function(mod, _print_str, "print_str");
  awsm_register_function(mod, _print_f32, "print_f32");
  awsm_register_function(mod, _print_f64, "print_f64");
  awsm_register_function(mod, _require_f64, "require_f64");
  awsm_register_function(mod, _require_f32, "require_f32");
  awsm_register_function(mod, _require_i64, "require_i64");
  awsm_register_function(mod, _require_i32, "require_i32");
  awsm_register_function(mod, _sbrk, "sbrk");
  awsm_register_function(mod, wasm_fork_stack, "awsm_fork");
  awsm_register_function(mod, _new_coroutine, "new_coroutine");
  awsm_register_function(mod, _yield, "yield");
  awsm_register_function(mod, _get_heap_size, "get_heap_size");
  awsm_register_function(mod, _set_heap_size, "set_heap_size");
  awsm_register_function(mod, _wasm_error, "awsm_error");
  awsm_set_error_callback(standard_error_callback);
  return mod;
}


bool awsm_process(wasm_module * module, u64 steps_total){
  
  u64 steps_target = steps_total + module->steps_executed;
  
  u64 group = module->steps_per_context_switch;
  if(module->stacks == NULL)
    return false;
  while(module->steps_executed < steps_target){
    u64 i = module->current_stack;
    while(module->stacks[i] == NULL || module->stacks[i]->error != NULL){
      i++;
      if(i >= module->stack_count) i = 0;
      if(i == module->current_stack)
	return false;
    }
    module->current_stack = i;
    wasm_exec_code2(module->stacks[i], group);    
    module->steps_executed += group;
    if(module->stacks[i]->keep_alive == false && wasm_stack_is_finalized(module->stacks[i])){
      wasm_delete_stack(module->stacks[i]);
      module->stacks[i] = NULL;
    }
    module->current_stack += 1;
    if(module->current_stack >= module->stack_count) module->current_stack = 0;
  }
  return true;
}

stack * awsm_load_thread(wasm_module * module, const char * func){
  return awsm_load_thread_arg(module, func, 0);
}

stack * awsm_load_thread_arg(wasm_module * module, const char * func, u32 arg){
  if(module == NULL){
    ERROR("Module not initialized\n");
  }
  stack * ctx = alloc0(sizeof(ctx[0]));
  wasm_module_add_stack(module, ctx);
  int main_index = awsm_get_function(module, func);
  if(main_index == -1){
    log("Unable to lookup function '%s'\n", func);
    return NULL;
  }
  int arg_cnt = awsm_get_function_arg_cnt(module, main_index);
  
  int ret_cnt = awsm_get_function_ret_cnt(module, main_index);
  logd("Load Thread. (%s) %x (%i) -> %i\n", func, main_index, arg_cnt, ret_cnt);
  u8 code[128] = {0};
  code[0] = WASM_INSTR_I32_CONST;
  code[1] = 31;
  u32 offset = 2;
  for(int i = 0; i < arg_cnt; i++){
    code[offset] = WASM_INSTR_I32_CONST;
    offset += 1;
    int len = encode_u64_leb((u64)(i == 0 ? arg : 0), code + offset);
    offset += len;
  }
  code[offset] = WASM_INSTR_CALL;
  offset += 1;
  offset += encode_u64_leb((u64)main_index, code + offset);
  for(int i = 0; i < ret_cnt; i++){
    code[offset + i] = WASM_INSTR_DROP;
  }
  offset += ret_cnt;
  
  ctx->initializer = mem_clone(code, offset);
  ctx->initializer_size = offset;
  wasm_load_code(ctx, ctx->initializer, offset);
  return ctx;
}

void awsm_diagnostic(bool diagnostic_level_enabled){
  awsm_log_diagnostic = diagnostic_level_enabled;
}

void awsm_push_i32(stack * s, int32_t v){
  wasm_push_i32(s, v);
}

void awsm_push_i64(stack * s, int64_t v){
  wasm_push_i64(s, v);
}

void awsm_push_u32(stack * s, uint32_t v){
  wasm_push_u32(s, v);
}

void awsm_push_u64(stack * s, uint64_t v){
  wasm_push_u64(s, v);
}

void awsm_push_f32(stack * s, float v){
  wasm_push_f32(s, v);
}

void awsm_push_f64(stack * s, double v){
  wasm_push_f64(s, v);
}

int32_t awsm_pop_i32(stack * s){
  int32_t v;
  wasm_pop_i32(s, &v);
  return v;  
}
int64_t awsm_pop_i64(stack * s){
  int64_t v;
  wasm_pop_i64(s, &v);
  return v;  
}
uint32_t awsm_pop_u32(stack * s){
  uint32_t v;
  wasm_pop_u32(s, &v);
  return v;  
}
uint64_t awsm_pop_u64(stack * s){
  uint64_t v;
  wasm_pop_u64(s, &v);
  return v;  
}
float awsm_pop_f32(stack * s){
  float v;
  wasm_pop_f32(s, &v);
  return v;  
}

double awsm_pop_f64(stack * s){
  double v;
  wasm_pop_f64(s, &v);
  return v;  
}

void * awsm_pop_ptr(stack * s){
  return s->module->heap->heap + awsm_pop_u32(s);
}

void awsm_thread_keep_alive(stack * s, int keep_alive){
  wasm_execution_stack_keep_alive(s, keep_alive);
}

void * awsm_module_heap_ptr(wasm_module * mod){
  return mod->heap->heap;
}

char * awsm_thread_error(wasm_execution_stack * s){
  return s->error;
}

wasm_module * awsm_stack_module(wasm_execution_stack * s){
  return s->module;
}

size_t awsm_heap_size(wasm_module * mod);
void awsm_heap_increase(wasm_module * mod, size_t amount);


// debug api

void breakcheck_run(wasm_execution_stack * ctx){
  wasm_module * mod = ctx->module;
  for(u32 i = 0; i < mod->breakcheck_count; i++){
    mod->breakcheck[i](ctx,mod->breakcheck_context[i]);
  }
}

bool breakcheck_enabled(wasm_execution_stack * ctx){
  return ctx->module->enabled_breakchecks > 0;
}

breakcheck_id awsm_debug_attach_breakcheck(wasm_module * mod, breakcheck_callback f, void * user_context){
  int id = -1;
  for(size_t i = 0; i < mod->breakcheck_count; i++){
    if(mod->breakcheck[id] == NULL){
      id = i;
      break;
    }
  }
  if(id == -1){
    id = mod->breakcheck_count;
    mod->breakcheck_count += 1;
    mod->breakcheck = realloc(mod->breakcheck, mod->breakcheck_count * sizeof(mod->breakcheck[0]));
    mod->breakcheck_context = realloc(mod->breakcheck_context, mod->breakcheck_count * sizeof(mod->breakcheck_context[0]));
  }
  mod->breakcheck[id] = f;
  mod->breakcheck_context[id] = user_context;
  mod->enabled_breakchecks += 1;
  return id;
}

void awsm_debug_remove_breakcheck(wasm_module * mod, breakcheck_id id){
  mod->breakcheck[id] = NULL;
  mod->breakcheck_context[id] = NULL;
  mod->enabled_breakchecks -= 1;
}

int awsm_debug_next_instr(wasm_execution_stack * ctx)
{
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_code_reader * rd = &f->rd;
  wasm_instr instr = reader_peek1(rd);
  return instr;
}

int awsm_debug_location(wasm_execution_stack * ctx){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_code_reader * rd = &f->rd;
  return rd->offset;
}

int awsm_debug_source_address(wasm_execution_stack * ctx){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_code_reader * rd = &f->rd;
  int func_id = f->func_id;
  wasm_module * mod = ctx->module;
  if((int)mod->func_count < func_id)
    return -1;
  if(mod->func[func_id].name == NULL)
    return -1;
  u32 code_offset = mod->func[func_id].code_offset + rd->offset;
  return (int)code_offset;

}

int awsm_debug_source_location(wasm_execution_stack * ctx, char * out_filename, int * out_line){
  UNUSED(out_filename);
  UNUSED(out_line);
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  wasm_code_reader * rd = &f->rd;
  int func_id = f->func_id;
  wasm_module * mod = ctx->module;
  if((int)mod->func_count < func_id)
    return 1;
  if(mod->func[func_id].name == NULL)
    return 1;
  u32 code_offset = mod->func[func_id].code_offset + rd->offset;
  //printf("CODE OFFSET: %x\n", code_offset);
  return dwarf_source_location(mod->dwarf_debug_lines, mod->dwarf_debug_lines_size, code_offset, out_filename, out_line);

}

const char * awsm_debug_current_function(wasm_execution_stack * ctx){
  wasm_control_stack_frame * f = ctx->frames + ctx->frame_ptr;
  int func_id = f->func_id;
  wasm_module * mod = ctx->module;
  if(func_id < 0) return NULL;
  if((int)mod->func_count < func_id)
    return "unknown_function";
  return mod->func[func_id].name;
}

const char * awsm_debug_instr_name(int instr){
  if(instr > wasm_instr_count || instr < 0)
    return "UNKNOWN_INSTRUCTION";
  return wasm_instr_name[instr];
}



void writer_write(data_writer * writer, void * data, size_t count){
  if(writer->offset + count > writer->size){
    size_t newsize = (writer->size + count) * 1.2;
    writer->data = realloc(writer->data, newsize);
    writer->size = newsize;
  }
  memcpy(writer->data + writer->offset, data, count);
  writer->offset += count;
}
void writer_write_u8(data_writer * wd, u8 value){ writer_write(wd, &value, sizeof(value));}
void writer_write_u32(data_writer * wd, u32 value){ writer_write(wd, &value, sizeof(value));}
void writer_write_u64(data_writer * wd, u64 value){ writer_write(wd, &value, sizeof(value));}
void writer_write_i32(data_writer * wd, i32 value){ writer_write(wd, &value, sizeof(value));}


// -- Saving and load VM state. -- \\

// markerthing is used for checking sanity during load
u32 markerthing = 0x00BEEF00;

void frame_save(data_writer * wd, wasm_control_stack_frame * f, stack * stk){
  writer_write_u32(wd, markerthing);
  writer_write_i32(wd, f->block);
  writer_write_u32(wd, f->label_offset);
  writer_write_u32(wd, f->stack_pos);
  writer_write_u32(wd, f->localcount);
  writer_write_u32(wd, f->retcount);
  writer_write_i32(wd, f->func_id);
  wasm_code_reader rd = f->rd;

  if(rd.data >= stk->initializer && rd.data <= stk->initializer + stk->initializer_size){
    // executing initializer code.
    writer_write_u8(wd, 0);
    writer_write_u32(wd, rd.offset);
  }else{

    if(f->func_id >= 0){
      // Executing a function.
      writer_write_u8(wd, 2);
      writer_write_u32(wd, rd.offset);
    }else{
      wasm_heap * heap = stk->module->heap;
      // printf("%p %p %i\n", rd.data, heap->heap,
    if(rd.data >= heap->heap && rd.data < heap->heap + heap->capacity){
      // executing code directly from the heap.
      writer_write_u8(wd, 1);
      writer_write_u32(wd, rd.offset);
    }
    else{
      ERROR("Unknown function type, cannot save!\n");

    }
    }

  }

}

void stack_save(data_writer * wd, stack * stk){
  writer_write_u32(wd, markerthing);
  writer_write_u32(wd, stk->stack_ptr);  
  writer_write(wd, stk->stack, (stk->stack_ptr + 1) * sizeof(stk->stack[0]));

  writer_write_u32(wd, stk->initializer_size);
  writer_write(wd, stk->initializer, stk->initializer_size);
  
  writer_write_u32(wd, stk->frame_ptr);

  for(u32 i = 0; i <= stk->frame_ptr; i++)
    frame_save(wd, stk->frames + i, stk);
  writer_write_u32(wd, stk->label_capacity);
  writer_write(wd, stk->labels, stk->label_capacity * sizeof(stk->labels[0]));

  writer_write_u8(wd, stk->keep_alive);
  // keep_alive?
}

void module_save(data_writer * wd, wasm_module * mod){
  writer_write_u32(wd, markerthing);

  u32 stkcnt = 0;
  for(u32 i = 0 ; i < mod->stack_count; i++){
    if(mod->stacks[i] != NULL)
      stkcnt += 1;
  }
  writer_write_u32(wd, stkcnt);
  for(u32 i = 0 ; i < mod->stack_count; i++){
    if(mod->stacks[i] != NULL)
      stack_save(wd, mod->stacks[i]);
  }
  writer_write_u32(wd, mod->global_count);
  writer_write(wd, mod->globals, mod->global_count * sizeof(u64));
  writer_write_u64(wd, mod->heap->capacity);
  writer_write(wd, mod->heap->heap, mod->heap->capacity);
}

void awsm_module_save_state(wasm_module * mod, void ** buffer, size_t * size){
  // saves the heap and the execution stack.
  // assumes the module after load will be the same, so func related things are not touched
  // the global values are saved though.
  // [execution stacks]
  data_writer writer = {.data = NULL, .size = 0, .offset = 0};
  module_save(&writer, mod);
  *buffer = writer.data;
  *size = writer.offset;
}

void frame_load(data_reader * rd, wasm_control_stack_frame * f, stack * stk){
  ASSERT(reader_readu32_fixed(rd) == markerthing);
  f->block = reader_readi32_fixed(rd);
  f->label_offset = reader_readu32_fixed(rd);
  f->stack_pos = reader_readu32_fixed(rd);
  f->localcount = reader_readu32_fixed(rd);
  f->retcount = reader_readu32_fixed(rd);
  f->func_id = reader_readi32_fixed(rd);

  u8 type = reader_read1(rd);
  u32 offset = reader_readu32_fixed(rd);
  wasm_code_reader * rd2 = &f->rd;

  if(type == 0){
    rd2->data = stk->initializer;
    rd2->offset = offset;
    rd2->size = stk->initializer_size;
  }else if(type == 2){
    wasm_function * f2 = stk->module->func + f->func_id;
    rd2->data = f2->code;
    rd2->size = f2->length;
    rd2->offset = offset;
  }else if(type == 1){
    ERROR("UNSUPPORTED\n");

  }
}

void stack_load(data_reader * rd, stack * stk){
  ASSERT(reader_readu32_fixed(rd) == markerthing);
  stk->stack_ptr = reader_readu32_fixed(rd);
  stk->stack_capacity = stk->stack_ptr + 1;
  stk->stack = realloc(stk->stack, sizeof(stk->stack[0]) * stk->stack_capacity);

  reader_read(rd, stk->stack, (stk->stack_ptr + 1) * sizeof(stk->stack[0]));

  stk->initializer_size = reader_readu32_fixed(rd);
  stk->initializer = realloc(stk->initializer, stk->initializer_size);
  reader_read(rd, stk->initializer, stk->initializer_size);
  
  stk->frame_ptr = reader_readu32_fixed(rd);
  stk->frame_capacity = stk->frame_ptr + 1;
  stk->frames = realloc(stk->frames, stk->frame_capacity * sizeof(stk->frames[0]));
  for(u32 i = 0; i <= stk->frame_ptr; i++)
    frame_load(rd, stk->frames + i, stk);

  stk->label_capacity = reader_readu32_fixed(rd);
  stk->labels = realloc(stk->labels, stk->label_capacity * sizeof(stk->labels[0]));
  reader_read(rd, stk->labels, stk->label_capacity * sizeof(stk->labels[0]));

  stk->keep_alive = (bool)reader_read1(rd);

}

void module_load(data_reader * rd, wasm_module * mod){
  ASSERT(reader_readu32_fixed(rd) == markerthing);
  u32 stack_count = reader_readu32_fixed(rd);
  mod->stacks = realloc(mod->stacks, stack_count * sizeof(mod->stacks[0]));
  mod->stack_count = stack_count;
  for(u32 i = 0; i < stack_count; i++){
    stack_load(rd, mod->stacks[i]);
  }
  u32 global_count = reader_readu32_fixed(rd);
  if(global_count != mod->global_count)
    ERROR("Global count seems wrong!!\n");
  mod->globals = realloc(mod->globals, sizeof(mod->globals[0]) * mod->global_count);
  reader_read(rd, mod->globals, global_count * sizeof(mod->globals[0]));
  mod->heap->capacity = reader_readu64_fixed(rd);
  mod->heap->heap = realloc(mod->heap->heap, mod->heap->capacity);
  reader_read(rd, mod->heap->heap, mod->heap->capacity);
  ASSERT(rd->offset == rd->size);

}

void awsm_module_load_state(wasm_module * mod, void * buffer, size_t size){
  // loads the heap and the execution stack.
  data_reader reader = {.data = buffer, .size = size, .offset = 0};
  module_load(&reader, mod);
}
