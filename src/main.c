#include <iron/full.h>


typedef enum WASM_SECTION{
  WASM_CUSTOM_SECTION = 0,
  WASM_TYPE_SECTION,
  WASM_IMPORT_SECTION,
  WASM_FUNCTION_SECTION,
  WASM_TABLE_SECTION,
  WASM_MEMORY_SECTION,
  WASM_GLOBAL_SECTION,
  WASM_EXPORT_SECTION,
  WASM_START_SECTION,
  WASM_ELEMENT_SECTION,
  WASM_CODE_SECTION,
  WASM_DATA_SECTION
}wasm_section;

typedef enum WASM_INSTR{
  WASM_INSTR_UNREACHABLE = 0x0,
  WASM_INSTR_NOP = 0x01,
  WASM_INSTR_BLOCK = 0x02,
  WASM_INSTR_LOOP = 0x03,
  WASM_INSTR_IF = 0x04,
  WASM_INSTR_ELSE = 0x05,
  WASM_INSTR_END = 0x0B,
  WASM_INSTR_BR = 0x0C,
  WASM_INSTR_BR_IF = 0x0D,
  WASM_INSTR_BR_TABLE = 0x0E,
  WASM_INSTR_RETURN = 0x0F,
  WASM_INSTR_CALL = 0x10,
  WASM_INSTR_DROP = 0x1A,
  WASM_INSTR_SELECT = 0x1B,
  WASM_INSTR_CALL_INDIRECT = 0x11,
  WASM_INSTR_LOCAL_GET = 0x20,
  WASM_INSTR_LOCAL_SET = 0x21,
  WASM_INSTR_LOCAL_TEE = 0x22,
  WASM_INSTR_GLOBAL_GET = 0x23,
  WASM_INSTR_GLOBAL_SET = 0x24,
  WASM_INSTR_I32_LOAD = 0x28,
  WASM_INSTR_I64_LOAD = 0x29,
  WASM_INSTR_F32_LOAD = 0x30,
  WASM_INSTR_F64_LOAD = 0x31,
  WASM_INSTR_I32_STORE = 0x36,
  WASM_INSTR_I64_STORE32 = 0x3E,
  
  WASM_INSTR_MEMORY_SIZE = 0x3F,
  WASM_INSTR_MEMORY_GROW = 0x40,
  WASM_INSTR_I32_CONST = 0x41,
  WASM_INSTR_I64_CONST = 0x42,
  WASM_INSTR_F32_CONST = 0x43,
  WASM_INSTR_F64_CONST = 0x44,
  WASM_INSTR_I32_EQZ = 0x45,
  WASM_INSTR_I32_EQ = 0x46,
  WASM_INSTR_I32_NE = 0x47,
  WASM_INSTR_I32_LT_S = 0x48,
  WASM_INSTR_I32_LT_U = 0x49,
  WASM_INSTR_I32_GT_S = 0x4a,
  WASM_INSTR_I32_GT_U = 0x4B,
  WASM_INSTR_I32_LE_S = 0x4C,
  WASM_INSTR_I32_LE_U = 0x4D,
  WASM_INSTR_I32_GE_S = 0x4E,
  WASM_INSTR_I32_GE_U = 0x4F,
  
  WASM_INSTR_I64_EQZ = 0x50,
  WASM_INSTR_I64_EQ = 0x51,
  WASM_INSTR_I64_NE = 0x52,  
  WASM_INSTR_I64_LT_S = 0x53,
  WASM_INSTR_I64_LT_U = 0x54,
  WASM_INSTR_I64_GT_S = 0x55,
  WASM_INSTR_I64_GT_U = 0x56,
  WASM_INSTR_I64_LE_S = 0x57,
  WASM_INSTR_I64_LE_U = 0x58,
  WASM_INSTR_I64_GE_S = 0x59,
  WASM_INSTR_I64_GE_U = 0x5a,

  WASM_INSTR_F32_EQ = 0x5b,
  WASM_INSTR_F32_NE = 0x5c,
  WASM_INSTR_F32_LT = 0x5d,
  WASM_INSTR_F32_GT = 0x5e,
  WASM_INSTR_F32_LE = 0x5f,
  WASM_INSTR_F32_GE = 0x60,  

  WASM_INSTR_F64_EQ = 0x61,
  WASM_INSTR_F64_NE = 0x62,
  WASM_INSTR_F64_LT = 0x63,
  WASM_INSTR_F64_GT = 0x64,
  WASM_INSTR_F64_LE = 0x65,
  WASM_INSTR_F64_GE = 0x66,  

  WASM_INSTR_I32_ADD = 0x6a,
  WASM_INSTR_I32_SUB = 0x6B,
  WASM_INSTR_I32_MUL = 0x6C,
  WASM_INSTR_I32_DIV_S = 0x6D,
  WASM_INSTR_I32_DIV_U = 0x6E,
  WASM_INSTR_I32_REM_S = 0x6F,
  WASM_INSTR_I32_REM_U = 0x70,
  WASM_INSTR_I32_AND = 0x71,
  WASM_INSTR_I32_OR = 0x72,
  WASM_INSTR_I32_XOR = 0x73,
  WASM_INSTR_I32_SHL = 0x74,
  WASM_INSTR_I32_SHR_S = 0x75,
  WASM_INSTR_I32_SHR_U = 0x76,
  WASM_INSTR_I32_ROTL = 0x77,
  WASM_INSTR_I32_ROTR = 0x78,
  
  WASM_INSTR_I64_CLZ = 0x79,
  WASM_INSTR_I64_CTZ = 0x7A,
  WASM_INSTR_I64_POPCNT = 0x7B,
  WASM_INSTR_I64_ADD = 0x7C,
  WASM_INSTR_I64_SUB = 0x7D,
  WASM_INSTR_I64_MUL = 0x7E,
  WASM_INSTR_I64_DIV_S = 0x7F,
  WASM_INSTR_I64_DIV_U = 0x80,
  WASM_INSTR_I64_REM_S = 0x81,
  WASM_INSTR_I64_REM_U = 0x82,
  WASM_INSTR_I64_AND = 0x83,
  WASM_INSTR_I64_OR = 0x84,
  WASM_INSTR_I64_XOR = 0x85,
  WASM_INSTR_I64_SHL = 0x86,
  WASM_INSTR_I64_SHR_S = 0x87,
  WASM_INSTR_I64_SHR_U = 0x88,
  WASM_INSTR_I64_ROTL = 0x89,
  WASM_INSTR_I64_ROTR = 0x8A,

  WASM_INSTR_F32_ABS = 0x8B,
  WASM_INSTR_F32_NEG = 0x8C,
  WASM_INSTR_F32_CEIL = 0x8D,
  WASM_INSTR_F32_FLOOR = 0x8E,
  WASM_INSTR_F32_TRUNC = 0x8F,
  WASM_INSTR_F32_NEAREST = 0x90,
  WASM_INSTR_F32_SQRT = 0x91,
  WASM_INSTR_F32_ADD = 0x92,
  WASM_INSTR_F32_SUB = 0x93,
  WASM_INSTR_F32_MUL = 0x94,
  WASM_INSTR_F32_DIV = 0x95,
  WASM_INSTR_F32_MIN = 0x96,
  WASM_INSTR_F32_MAX = 0x97,
  WASM_INSTR_F32_COPYSIGN = 0x98,

  WASM_INSTR_F64_ABS = 0x99,
  WASM_INSTR_F64_NEG = 0x9A,
  WASM_INSTR_F64_CEIL = 0x9B,
  WASM_INSTR_F64_FLOOR = 0x9C,
  WASM_INSTR_F64_TRUNC = 0x9D,
  WASM_INSTR_F64_NEAREST = 0x9E,
  WASM_INSTR_F64_SQRT = 0x9F,
  WASM_INSTR_F64_ADD = 0xA0,
  WASM_INSTR_F64_SUB = 0xA1,
  WASM_INSTR_F64_MUL = 0xA2,
  WASM_INSTR_F64_DIV = 0xA3,
  WASM_INSTR_F64_MIN = 0xA4,
  WASM_INSTR_F64_MAX = 0xA5,
  WASM_INSTR_F64_COPYSIGN = 0xA6,  
  
  WASM_INSTR_I32_WRAP_I64 = 0xA7,
  WASM_INSTR_F64_REINTERPRET_I64 = 0xBF
  
  
  
}wasm_instr;

typedef enum WASM_TYPE{
  WASM_TYPE_BLOCK_EMPTY = 0x40,
  WASM_TYPE_I32 = 0x7F,
  WASM_TYPE_I64 = 0x7E,
  WASM_TYPE_F32 = 0x7D,
  WASM_TYPE_F64 = 0x7C
}wasm_type;

typedef enum WASM_IMPORT_TYPE{
  WASM_IMPORT_FUNC = 0,
  WASM_IMPORT_TABLE = 1,
  WASM_IMPORT_MEM = 2,
  WASM_IMPORT_GLOBAL = 3
}wasm_import_type;
typedef enum WASM_BUILTIN_FCN{
  WASM_BUILTIN_UNRESOLVED = 0,
  WASM_BUILTIN_REQUIRE_I32,
  WASM_BUILTIN_REQUIRE_I64,
  WASM_BUILTIN_REQUIRE_F32,
  WASM_BUILTIN_REQUIRE_F64,
  WASM_BUILTIN_PRINT_I32,
  WASM_BUILTIN_PRINT_I64,
  WASM_BUILTIN_PRINT_STR
}wasm_builtin_fcn;
typedef struct{
  void * code;
  size_t length;
  const char * name;
  const char * module;
  int type;
  u32 argcount;
  // unpack the code for better performance. This is skipped for now.
  //bool resolved; 
  bool import;
  wasm_builtin_fcn builtin;
}wasm_function;

// cheapass function type struct;
typedef struct{
  int argcount;

}wasm_ftype;

typedef struct
{
  u32 offset;
}wasm_global;

typedef struct{
  void * heap;
  size_t capacity;
}wasm_heap;

typedef struct{
  wasm_function * func;
  size_t func_count;
  size_t import_func_count;
  size_t local_func_count;

  wasm_ftype * types;
  size_t type_count;
  
  size_t global_heap_location;
  wasm_heap * heap;
}wasm_module;

void wasm_heap_min_capacity(wasm_heap * heap, size_t capacity){
  if(heap->capacity < capacity){
    size_t old_capacity = capacity;
    heap->heap = realloc(heap->heap, capacity);
    memset(heap->heap + old_capacity, 0, capacity - old_capacity);
    heap->capacity = capacity;
  }
}
void wasm_module_add_func(wasm_module * module){
  module->func_count += 1;
  module->func = realloc(module->func, module->func_count * sizeof(module->func[0]));;
  module->func[module->func_count - 1] = (wasm_function){0};
}

float fneg(float f){
  return -f;
}

f64 dneg(f64 f){
  return -f;
}

#define OP_EQZ(x)x == 0

#define BINARY_OP(type, op){\
  type a = {0}, b = {0};    \
  wasm_pop_##type(ctx, &b);\
  wasm_pop_##type(ctx, &a);			\
  wasm_push_##type(ctx, a op b);\
  }break;

#define BINARY_OPF(type, op){\
  type a = {0}, b = {0};    \
  wasm_pop_##type(ctx, &b);\
  wasm_pop_##type(ctx, &a);			\
  wasm_push_##type(ctx, op(a, b));		\
  }break;


#define UNARY_OPF(type, f){\
  type a = {0};    \
  wasm_pop_##type(ctx, &a);			\
  wasm_push_##type(ctx, f(a));			\
  }break;

#define UNSUPPORTED_OP(name){ERROR("UNsupported operation\n");}break;

// Load a WASM module from bytes
wasm_module * load_wasm_module(wasm_heap * heap, void * _data, size_t size){
  wasm_module module = {0};
  module.heap = heap;
  ASSERT(size > 8);
  
  u8 * data = _data;
  
  void advance(int bytes){
    data += bytes;
    size -= bytes;
  }
  u8 read1(){
    u8 b = data[0];
    advance(1);
    return b;
  }

  u64 readu64(){
    // read LEB128
    u8 chunk = 0;
    u64 value = 0;
    u32 offset = 0;
    while((chunk = read1()) > 0){
      value |= (0b01111111 & chunk) << offset;
      offset += 7;
      if((0b10000000 & chunk) == false)
	break;
    }
    return value;
  }
  
  u32 readu32(){
    return readu64();
  }

  i32 readi32(){
    // read LEB128
    u8 chunk = 0;
    i32 value = 0;
    u32 offset = 0;
    while((chunk = read1()) > 0)
      {
	value |= (0b01111111 & chunk) << offset;
	offset += 7;
	if((0b10000000 & chunk) == false)
	  break;
      }

    i32 value2 = (value << (32 - offset)) >>(32 - offset); 
    return value2;
  }

  void read(void * buffer, size_t len){
    ASSERT(len <= size);
    memcpy(buffer, data, len);
    data += len;
    size -= len;
  }

  size_t getloc(){
    return data - ((u8 *) _data);
  }
  
  char * readname(){
    u32 len = readu32();
    char * buffer = alloc(len + 1);
    read(buffer, len);
    buffer[len] = 0;
    return buffer;
  }
  
  const char * magic_header = "\0asm";
  bool contains_magic = memcmp(magic_header, data, 4) == 0;
  if(contains_magic == false){
    ERROR("File does not contain correct header");
    return NULL;
  }
  advance(4);

  const u8 wasm_version[]  = {1,0,0,0};
  bool contains_version = memcmp( wasm_version, data, 4) == 0;
  if(contains_version == false){
    ERROR("File does not contain correct header");
    return NULL;
  }
  advance(4);
  
  while(size > 0){
    wasm_section section = (wasm_section) read1();
    switch(section){
    case WASM_TYPE_SECTION:
      {
	u32 length = readu32();
	logd("Type section: %i bytes\n", length);
	u32 typecount = readu32();
	module.type_count = typecount;
	module.types = alloc0(sizeof(module.types[0]) * module.type_count);
	for(u32 typeidx = 0; typeidx < typecount; typeidx++){
	
	  u8 header = read1();
	  ASSERT(header == 0x60);
	  u32 paramcount = readu32();
	  for(u32 i = 0; i < paramcount; i++){
	    read1(); // discard
	  }

	  u32 returncount = readu32();
	  for(u32 i = 0; i < returncount; i++){
	    read1(); // discard
	  }
	  module.types[typeidx].argcount = paramcount;
	  
	}
	break;
      }
    case WASM_CUSTOM_SECTION:
      {
	u32 length = readu32();
	logd("Custom section %i\n", length);
	if(length > 0){
	  logd("Skip custom section");
	  advance(length);
	}
	continue;
      }
    case WASM_IMPORT_SECTION:
      {

	u32 length = readu32();
	u32 guard = size;
	u32 importCount = readu32();
	logd("Import count: %i\n", importCount);
	for(u32 i = 0; i < importCount; i++){
	  char * modulename = readname();
	  char * name = readname();
	  wasm_import_type itype = read1();
	  switch(itype){
	  case WASM_IMPORT_FUNC:
	    {

	      u32 typeindex = readu32();
	      logd("IMPORT FUNC: %s %s %i\n", modulename, name, typeindex);
	      // imported funcs comes before defined ones.
	      wasm_module_add_func(&module);
	      wasm_function * f = module.func + module.import_func_count;
	      module.import_func_count += 1;


	      f->name = name;
	      f->import = true;
	      f->type = typeindex;
	      f->module = modulename;
	      break;
	    }
	  case WASM_IMPORT_TABLE:
	    {
	      u8 elemtype = read1();
	      ASSERT(elemtype == 0x70);
	      u8 limitt = read1();
	      u32 min = 0, max = 0;
	      if(limitt == 0){
		min = readu32();
	      }else{
		min = readu32();
		max = readu32();
	      }
	      logd("TABLE: %i %i\n", min, max, elemtype);
	      ERROR("Not supported");
	    }
	    break;
	  case WASM_IMPORT_MEM:
	    {
	      u8 hasMax = read1();
	      u32 min = readu32(), max = 0;
	    
	      if(hasMax){
		max = readu32();
	      }
	      
	      logd("IMPORT MEMORY: %i %i %i\n", hasMax, min, max);
	      
	      break;
	    }
	  case WASM_IMPORT_GLOBAL:
	    {
	      wasm_type type = (wasm_type) read1();
	      bool mut = read1();
	      logd("IMPORT GLOBAL: %s %s %s %i\n", module, name, mut ? "mutable" : "const", type);
	      break;
	    }
	  }
	}
	if(guard != size + length)
	  ERROR("Parse imbzxalance %i != %i + %i (%x)!\n", guard, size, length, getloc());
	break;

	
      }
    case WASM_EXPORT_SECTION:
      {
	u32 length = readu32();
	logd("EXPORT section: length: %i\n", length);
	u32 exportcount = readu32();
	for(u32 i = 0; i < exportcount; i++){
	  char * name = readname();
	  wasm_import_type etype = (wasm_import_type) read1();
	  switch(etype){
	  case WASM_IMPORT_FUNC:
	    {
	      u32 index = readu32();

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
	      u32 memory_index = readu32();
	      logd("MEMORY %i\n", memory_index);
	      break;
	    }
	  case WASM_IMPORT_GLOBAL:
	    {
	      u32 global_index = readu32();
	      logd("GLOBAL %i\n", global_index);
	      break;			 
	    }
	  }
	}
	break;
      }
    case WASM_FUNCTION_SECTION:
      {
	u32 length = readu32();
	logd("Function section: length: %i\n", length);
	u32 guard = size;
	u32 funccount = readu32();
	logd("count: %i\n", funccount);
       
	for(u32 i = 0; i < funccount; i++){
	  var funcindex = module.import_func_count + i;
	  u32 f = readu32();
	  logd("Func %i: %i %i\n",i, f, funcindex);
	  if(module.func_count <= funcindex)
	    wasm_module_add_func(&module);
	  module.func[funcindex].type = f;
	  module.func[funcindex].argcount = module.types[f].argcount;
	}
	if(guard != size + length)
	  ERROR("Parse imbalance!\n");
	//advance(length);
	break;
      }
    case WASM_CODE_SECTION:
      {
	u32 length = readu32();
	logd("Code section: length: %i\n", length);
	u32 guard = size;
	u32 funccount = readu32();
	logd("Code Count: %i\n", funccount);
	for(u32 i = 0; i < funccount; i++){
	  u32 codesize = readu32();
	  int funcindex = i + module.import_func_count;
	  module.func[funcindex].code = data;
	  module.func[funcindex].length = codesize;
	  advance(codesize);
	}

	if(guard != size + length)
	  ERROR("Parse imbalance! %i != %i + %i\n", guard, size, length);
      }
      break;
    case WASM_DATA_SECTION:
      {
	u32 length = readu32();
	u32 guard = size;
	u32 datacount = readu32();
	bool isGlobal = false;
	for(u32 i = 0; i < datacount; i++){
	  u32 memidx = readu32();
	  ASSERT(memidx == 0);
	  u32 offset = 0;

	  while(true){
	    wasm_instr instr = (wasm_instr)read1();
	    switch(instr){
	    case WASM_INSTR_I32_CONST:
	      {
		i32 _offset = readi32();
		offset = _offset;
		break;
	      }
	    case WASM_INSTR_GLOBAL_GET:
	      {
		i32 _offset = readi32();
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

	  u32 bytecount = readu32();
	  logd("DATA SECTION: %i %i %s\n", offset, bytecount, isGlobal ? "global" : "local");
	  wasm_heap_min_capacity(module.heap, bytecount + offset + 1);
	  read(module.heap->heap + offset, bytecount);
	  
	  //printf(" %s\n", module.heap->heap + offset);
	}
	if(guard != size + length)
	  ERROR("Parse imbalance!\n");
	
      break;
      }
     default:
       {
	 u32 length = readu32();
	 logd("unsupported section%i, 0x%X\n", section, length);

	 advance(length);
       }  
    }
  }
  return iron_clone(&module, sizeof(module));
}

// everything on the wasm execution stack is a 64bit value.
typedef struct{
  u64 * stack;
  size_t stack_capacity;
  size_t stack_ptr;
  wasm_module * module;
}wasm_execution_context;

void wasm_push_data(wasm_execution_context * ctx, void * data, size_t size){
  size_t new_size = ctx->stack_ptr + (size + 7) / 8;
  if(new_size > ctx->stack_capacity){
    ctx->stack = realloc(ctx->stack, 8 * (ctx->stack_capacity = (ctx->stack_capacity + 1) * 2));
    logd("increasing stack to %i\n", ctx->stack_capacity);
  }
  if(size < 8)
    memset(ctx->stack + ctx->stack_ptr, 0, sizeof(ctx->stack[0]));
  memmove(ctx->stack + ctx->stack_ptr, data, size);
  ctx->stack_ptr = new_size;
}

void wasm_push_i32(wasm_execution_context * ctx, i32 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

void wasm_push_u32(wasm_execution_context * ctx, u32 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

void wasm_push_u64(wasm_execution_context * ctx, u64 v){
  wasm_push_data(ctx, &v, sizeof(v));
}
void wasm_push_i64(wasm_execution_context * ctx, i64 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

void wasm_push_f32(wasm_execution_context * ctx, f32 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

void wasm_push_f64(wasm_execution_context * ctx, f64 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

void wasm_pop_data(wasm_execution_context * ctx, void * out){
  ASSERT(ctx->stack_ptr > 0);
  ctx->stack_ptr -= 1;
  memmove(out, ctx->stack + ctx->stack_ptr, 8);
}
void wasm_stack_drop(wasm_execution_context * ctx){
  ASSERT(ctx->stack_ptr > 0);
  ctx->stack_ptr -= 1;
}

void wasm_pop_i32(wasm_execution_context * ctx, i32 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = (i32)val;
}
void wasm_pop_u32(wasm_execution_context * ctx, u32 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = (u32)val;
}

void wasm_pop_i64(wasm_execution_context * ctx, i64 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = val;
}

void wasm_pop2_i64(wasm_execution_context * ctx, i64 * out){
  union{
    i64 val;
    struct{
      i32 x;
      i32 y;
    };
  }w;
  wasm_pop_i32(ctx, &w.x);
  wasm_pop_i32(ctx, &w.y);

  *out = w.val;
}

void wasm_pop_f32(wasm_execution_context * ctx, f32 *out){
  union{
    f32 o;
    u64 d;
  }w;
  wasm_pop_data(ctx, &w.d);
  *out = w.o;
}

void wasm_pop_f64(wasm_execution_context * ctx, f64 * out){
  union{
    f64 o;
    u64 d;
  }w;
  wasm_pop_data(ctx, &w.d);
  *out = w.o;
}

void wasm_pop_u64(wasm_execution_context * ctx, u64 * out){
  wasm_pop_data(ctx, out);
  logd("WASM POP u64: %p\n", *out);
}

void wasm_push_u64r(wasm_execution_context * ctx, u64 * in){
  logd("PUSH u64r: %p\n", *in);
  wasm_push_data(ctx, in, sizeof(in[0]));
}
//awsm VM
static int stack_frames = 0;
void wasm_exec_code(wasm_execution_context * ctx, u8 * _code, size_t codelen, bool funccall, u32 argcount){
  stack_frames += 1;
  wasm_module * mod = ctx->module;
  u32 offset = 0;
  u8 read1(){
    u8 v = _code[offset];
    offset += 1;
    return v;
  }
  u32 block = 0;
  u32 labels[20] = {0};
  u32 label_return[20] = {0};
  void push_label(){
    labels[block] = offset;
  }
  void pop_label(){
    offset = labels[block];
  }
  UNUSED(pop_label);

  u64 readu64(){
    // read LEB128
    u8 chunk = 0;
    u64 value = 0;
    u32 offset = 0;
    while((chunk = read1()) > 0){
      value |= (0b01111111 & chunk) << offset;
      offset += 7;
      if((0b10000000 & chunk) == false)
	break;
    }
    return value;
  }
  
  u32 readu32(){
    return readu64();
  }

  f32 readf32(){
    f32 v = 0;
    memcpy(&v, _code + offset, sizeof(v));
    offset += sizeof(v);
    logd("READ f32: %f\n", v);
    return v;
  }

  f64 readf64(){
    f64 v = 0;
    memcpy(&v, _code + offset, sizeof(v));
    offset += sizeof(v);
    return v;
  }

  i64 readi64() {
    // read LEB128
    i64 value = 0;
    u32 shift = 0;
    u8 chunk;
   do {
     chunk = read1();
     value |= (((u64)(chunk & 0x7f)) << shift);
     shift += 7;
   } while (chunk >= 128);
   if (shift < 64 && (chunk & 0x40))
     value |= (-1ULL) << shift;
   return value;
 }

  i32 readi32(){
    return (i32)readi64();
  }


  u32 localcount = funccall ? readu32() : 0;
  u32 localcount2 = 0;
  for(u32 j = 0; j < localcount; j++){
    u32 elemcount = readu32();
    u8 type = read1();
    localcount2 += elemcount;
    //logd("%i of 0x%x\n", elemcount, type);
    UNUSED(type);
    UNUSED(elemcount);
  }
  localcount = localcount2;
  localcount += argcount;
  u64 locals[localcount];
  for(u32 i = 0; i < localcount; i++)
    locals[i] = 0;
  for(u32 i = 0; i < argcount; i++){
    wasm_pop_u64(ctx, locals + argcount - 1 - i);
  }

  logd("LOCAL COUNT: %i\n", localcount);
  
  UNUSED(readi32);

  UNUSED(codelen);
  wasm_instr move_to_end_of_block(){
    u32 blk = block;
    while(offset < codelen){
      wasm_instr instr = read1();
      logd("SKIP INSTR: %x\n", instr);
      if(instr >= WASM_INSTR_LOCAL_GET && instr <= WASM_INSTR_GLOBAL_SET)
	{
	// all these has one integer.
	  readu64();
	  continue;
	}
      if(instr >= WASM_INSTR_I32_LOAD && instr <= WASM_INSTR_I64_STORE32){
	readi64();
	readi64();
	continue;
      }
      if(instr >= WASM_INSTR_MEMORY_SIZE && instr <= WASM_INSTR_I64_CONST){
	readi32();
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
	read1();
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
	readu32();
	break;
      case WASM_INSTR_RETURN:
	break; // dont return while skip block
      case WASM_INSTR_CALL:
	readu32();
	break;
      case WASM_INSTR_CALL_INDIRECT:
	readu32();
	read1();
	break;
      default:
	ERROR("Unhandled instruction %x\n", instr);
      }
    }
    return WASM_INSTR_UNREACHABLE;
  }
  while(offset < codelen){
    wasm_instr instr = read1();
    logd("INSTRUCTION: %x\n", instr);
    switch(instr){
    case WASM_INSTR_BLOCK:
      {
	u8 blktype = read1();
	
	block += 1;
	if(blktype != 0x40){
	  u8 blkret = blktype;
	  label_return[block] = blkret;
	}

      }
      break;
    case WASM_INSTR_LOOP:
      {
	u8 blktype = read1();
	
	block += 1;
	push_label();
	if(blktype != 0x40){
	  u8 blkret = blktype;
	  label_return[block] = blkret;
	}
	
      }
      break;
    case WASM_INSTR_IF:
      {
	block += 1;
	u8 blktype = read1();
	if(blktype != 0x40){
	  u8 blkret = blktype;
	  label_return[block] = blkret;
	}
	u64 cnd;
	wasm_pop_u64(ctx, &cnd);
	if(cnd){
	  logd("ENTER IF %x\n", read1());
	  offset -= 1;
	}else{
	  logd("ENTER ELSE\n");	
	  wasm_instr end = move_to_end_of_block();
	  switch(end){
	  case WASM_INSTR_ELSE:
	    logd("Found ELSE!!\n");
	    break;
	  case WASM_INSTR_END:
	    // this happens
	    logd("Found END!!\n");

	    block -= 1;
	    
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
	wasm_instr end = move_to_end_of_block();
	switch(end){
	case WASM_INSTR_END:
	  block -= 1;
	  break;
	default:
	  ERROR("UNSUPPORTED END INstruction: %x\n", end);
	}
      }
      break;
    case WASM_INSTR_END:
      {
	if(block == 0){
	  stack_frames -= 1;
	  return;
	}
	block -= 1;
	logd("END LOOP\n");
      }
      break;
    case WASM_INSTR_BR:
      {
      wasm_instr_br:;
	u32 brindex = readu32();
	ASSERT(brindex == 0);
	
	if(labels[block]){
	  // loop block not sure what brindex does.
	  pop_label();
	}else{
	  logd("BRANCH -> MOVE TO END\n");
	  wasm_instr end = move_to_end_of_block();
	  ASSERT(end == WASM_INSTR_END);
	  labels[block] = 0;
	  block -= 1;
	}
      }
      break;
    case WASM_INSTR_BR_IF:
      {

	u64 x;
	wasm_pop_u64(ctx, &x);
	logd("BR IF %x\n");
	if(x)
	  goto wasm_instr_br;
	readu32();
	//else continue..
      }
      break;
    case WASM_INSTR_RETURN:
      {
	while(block > 0){
	  if(label_return[block] != 0){
	    wasm_stack_drop(ctx);
	    label_return[block] = 0;
	  }
	  block--;
	}
      }
      break;
        case WASM_INSTR_CALL:
      {
	u32 fcn = read1();
	if(fcn > mod->func_count){
	  ERROR("Unknown function %i\n", fcn);
	}
	wasm_function * f = mod->func + fcn;
	if(f->import){
	  logd("CALL BUILTIN %i\n", fcn);
	  if(f->builtin == WASM_BUILTIN_UNRESOLVED){
	    bool nameis(const char * x){
	      return strcmp(x, f->name) == 0;
	    }
	    if(nameis("print_i32")){
	      f->builtin = WASM_BUILTIN_PRINT_I32;
	    }else if(nameis("print_i64")){
	      f->builtin = WASM_BUILTIN_PRINT_I64;
	    }else if(nameis("print_str")){
	      f->builtin = WASM_BUILTIN_PRINT_STR;
	    }else if(nameis("require_i32")){
	      f->builtin = WASM_BUILTIN_REQUIRE_I32;
	    }else if(nameis("require_i64")){
	      f->builtin = WASM_BUILTIN_REQUIRE_I64;
	    }else if(nameis("require_f32")){
	      f->builtin = WASM_BUILTIN_REQUIRE_F32;
	    }else if(nameis("require_f64")){
	      f->builtin = WASM_BUILTIN_REQUIRE_F64;
	    }else{
	      ERROR("Unknown import: %s\n", f->name);
	    }
	  }

	  // weird stuff:
	  // apparantly when calling external methods, emcc thinks its a 32 bit stack
	  // so 64bit values are in chunks of 32 bit.
	  
	  switch(f->builtin){
	  case WASM_BUILTIN_REQUIRE_I32:
	    {
	      i32 a, b;
	      wasm_pop_i32(ctx, &a);
	      wasm_pop_i32(ctx, &b);
	      log("REQUIRE I32 %i == %i\n", b, a);
	      if(a != b){
		ERROR("Require: does not match\n");
	      }
	    }
	    break;
	  case WASM_BUILTIN_REQUIRE_I64:
	    {
	      i64 a, b;
	      wasm_pop2_i64(ctx, &a);
	      wasm_pop2_i64(ctx, &b);
	      log("REQUIRE I64 %i == %i\n", b, a);
	      if(a != b){
		ERROR("Require: does not match\n");
	      }
	    }
	    break;
	  case WASM_BUILTIN_REQUIRE_F32:
	    {
	      f32 a, b;
	      wasm_pop_f32(ctx, &a);
	      wasm_pop_f32(ctx, &b);
	      log("REQUIRE f32 %f == %f\n", b, a, fabs(a - b) < 0.0001f);
	      if(fabs(a - b) > 0.000001){
		ERROR("Require: does not match\n");
	      }
	    }
	    break;
	  case WASM_BUILTIN_REQUIRE_F64:
	    {
	      f64 a, b;
	      wasm_pop_f64(ctx, &a);
	      wasm_pop_f64(ctx, &b);
	      log("REQUIRE f64 %f == %f\n", b, a);
	      if(a != b){
		ERROR("Require: does not match\n");
	      }
	    }
	    break;
	  case WASM_BUILTIN_PRINT_I32:
	    {
	      i32 v;
	      wasm_pop_i32(ctx, &v);
	      log("I32: %i\n", v);
	    }
	    break;
	  case WASM_BUILTIN_PRINT_I64:
	    {
	      i64 v;
	      wasm_pop_i64(ctx, &v);
	      log("I64: %p\n", v);
	    }
	    break;
	  case WASM_BUILTIN_PRINT_STR:
	    {
	      i32 v;
	      wasm_pop_i32(ctx, &v);
	      char * str = (mod->heap->heap + v);
	      v = printf("%s", str);
	      wasm_push_i32(ctx, v);
	    }
	    break;
	  default:
	    ERROR("Invalid builtin %i\n", f->builtin);
	    break;
	  }
	}else{
	  if(fcn == 6){
	    i64 x= 0;
	    wasm_pop_i64(ctx, &x);
	    logd("top of stack: %p\n", x);
	    wasm_push_i64(ctx, x);

	  }
	  logd("-------------%i CALL %s (%i)\n", stack_frames,f->name, fcn);
	  wasm_exec_code(ctx, f->code, f->length, true, f->argcount);
	  u64 v;
	  if(ctx->stack_ptr > 0){
	    wasm_pop_u64(ctx, &v);
	    wasm_push_u64(ctx, v);
	    logd("-------------- %i RETURNED %s %i \n", stack_frames, f->name, v);
	  }

	  //printf("return..\n");
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
	//printf("SELECT X: %p Y: %p S: %p\n", x, y, s);
	u64 result = (s != 0) ? y : x;
	//printf("SELECT RESULT %p\n", result);
	wasm_push_u64(ctx, result);
      }
      break;
      
    case WASM_INSTR_LOCAL_SET:
      {
	u32 local = readu32();
	ASSERT(local < localcount);
	logd("Local set: %i\n", local);
	wasm_pop_u64(ctx, locals + local);
	break;
      }
    case WASM_INSTR_LOCAL_GET:
      {

	u32 local = readu32();
	ASSERT(local < localcount);
	u64 l = locals[local];
	wasm_push_u64(ctx, l);
	logd("Local get %i: %i\n", local, l);
	break;
      }
    case WASM_INSTR_LOCAL_TEE:
      {
	u32 local = readu32();
	ASSERT(local < localcount);
	u64 value;
	wasm_pop_u64(ctx, &value);
	wasm_push_u64(ctx, value);	
	locals[local] = value;
	logd("Set local %i to %i\n", local, value);
      }
      break;
    case WASM_INSTR_GLOBAL_SET:
      {
	u32 global_index = readu32();
	ERROR("GLOBAL SET: %i\n", global_index);
	break;
      }
    case WASM_INSTR_GLOBAL_GET:
      {
	u32 global_index = readu32();
	ERROR("GLOBAL SET: %i\n", global_index);
	break;
      }


    case WASM_INSTR_I32_LOAD:
      {
	u32 align = readu32();
	u32 offset = readu32();
	UNUSED(align);
	i32 addr;
	wasm_pop_i32(ctx, &addr);
	i32 * valptr = (mod->heap->heap + addr + offset );
	wasm_push_i32(ctx, valptr[0]);
	break;
      }
      break;
    case WASM_INSTR_I64_LOAD:
      {
	u32 align = readu32();
	u32 offset = readu32();
	UNUSED(align);
	i32 addr;
	wasm_pop_i32(ctx, &addr);
	i64 * valptr = (mod->heap->heap + addr + offset );
	wasm_push_i64(ctx, valptr[0]);
	break;
      }
      break;
    case WASM_INSTR_F32_LOAD:
      {
	u32 align = readu32();
	u32 offset = readu32();
	UNUSED(align);
	i32 addr;
	wasm_pop_i32(ctx, &addr);
	f32 * valptr = (mod->heap->heap + addr + offset );
	wasm_push_f32(ctx, valptr[0]);
	break;
      }
      break;
    case WASM_INSTR_F64_LOAD:
      {
	u32 align = readu32();
	u32 offset = readu32();
	UNUSED(align);
	i32 addr;
	wasm_pop_i32(ctx, &addr);
	f64 * valptr = (mod->heap->heap + addr + offset );
	wasm_push_f64(ctx, valptr[0]);
	break;
      }
      break;
      case WASM_INSTR_I32_CONST:
      {
	i32 x = readi32();
	wasm_push_i32(ctx, x);
      }
      break;
    case WASM_INSTR_I64_CONST:
      {
	i64 x = readi64();
	wasm_push_i64(ctx, x);
      }
      break;
    case WASM_INSTR_F32_CONST:
      {
	f32 v = readf32();
	wasm_push_f32(ctx, v);
      }
      break;
    case WASM_INSTR_F64_CONST:
      {
	f64 v = readf64();
	wasm_push_f64(ctx, v);
      }
      break;
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
    case WASM_INSTR_I64_GE_S:
      BINARY_OP(i64, >=);
    case WASM_INSTR_I64_GE_U:
      BINARY_OP(u64, >=);

    case WASM_INSTR_F32_EQ:
      BINARY_OP(f32, ==);
    case WASM_INSTR_F32_NE:
      BINARY_OP(f32, !=);
    case WASM_INSTR_F32_LT:
      BINARY_OP(f32, <);
    case WASM_INSTR_F32_GT:
      BINARY_OP(f32, >);
    case WASM_INSTR_F32_LE:
      BINARY_OP(f32, <=);
    case WASM_INSTR_F32_GE:
      BINARY_OP(f32, <=);

    case WASM_INSTR_F64_EQ:
      BINARY_OP(f64, ==);
    case WASM_INSTR_F64_NE:
      BINARY_OP(f64, !=);
    case WASM_INSTR_F64_LT:
      BINARY_OP(f64, <);
    case WASM_INSTR_F64_GT:
      BINARY_OP(f64, >);
    case WASM_INSTR_F64_LE:
      BINARY_OP(f64, <=);
    case WASM_INSTR_F64_GE:
      BINARY_OP(f64, <=);
      
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
    case WASM_INSTR_I32_WRAP_I64:
      {
	i64 a = {0};
	wasm_pop_i64(ctx, &a);
	wasm_push_i64(ctx, a);
      }
      break;
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
    UNARY_OPF(f32, fneg);
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
    UNARY_OPF(f64, dneg);
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

    
    break;
    default:
      ERROR("Cannot execute opcode %x\n", instr);
      
    }
  }
  stack_frames -= 1;
}

int main(int argc, char ** argv){

  wasm_execution_context ctx ={0};
  char * file = NULL;
  char * entrypoint = NULL;
  bool diagnostic = false;
  for(int i = 1; i < argc; i++){
    if(strcmp(argv[i], "--diagnostic") == 0){
      diagnostic = true;
      continue;
    }
    if(file == NULL)
      file = argv[i];
    else if(entrypoint == NULL)
      entrypoint = argv[i];
  }
  if(file == NULL)
    goto print_help;
  if(!diagnostic)
    logd_enable = false;
  
  size_t buffer_size = 0;
  void * data = read_file_to_buffer(file, &buffer_size);
  wasm_heap heap = {0};
  wasm_module * mod = load_wasm_module(&heap, data, buffer_size);
  ctx.module = mod;
  int funcindex = -1;
  if(entrypoint == NULL)
    return 0;
  for(size_t i = 0; i < mod->func_count; i++){
    if(mod->func[i].name != NULL){
      logd("Function %i: %s\n", i, mod->func[i].name);
      if(strcmp(mod->func[i].name, entrypoint) == 0){
	logd("Execute this\n");
	funcindex = i;
      }
    }
  }

  if(funcindex != -1){
    logd("Executing...\n");
    wasm_push_i32(&ctx, 0);
    wasm_push_i32(&ctx, 0);
    u8 some_code[] = {WASM_INSTR_CALL, (u8) funcindex};
    wasm_exec_code(&ctx, some_code, sizeof(some_code), false, 0);
  }
  
  return 0;

 print_help:
  printf("Usage: awsm [file] [entrypoint] [--diagnostic] \n");
  return 1;
}
