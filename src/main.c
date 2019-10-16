
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <stdarg.h>
#include <signal.h>
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef float f32;
typedef double f64;
#define UNUSED(x) (void)(x)

static void _error(const char * file, int line, const char * msg, ...){
  UNUSED(file);UNUSED(line);UNUSED(msg);
  char buffer[1000];  
  va_list arglist;
  va_start (arglist, msg);
  vsprintf(buffer,msg,arglist);
  va_end(arglist);
  printf("%s\n", buffer);
  printf("Got error at %s line %i\n", file,line);
  raise(SIGINT);
  exit(10);
  raise(SIGINT);
}

#define log _log
#define ERROR(msg,...) _error(__FILE__,__LINE__,msg, ##__VA_ARGS__)
#define ASSERT(expr) if(__builtin_expect(!(expr), 0)){ERROR("Assertion '" #expr "' Failed");}

bool logd_enable = true;
static void logd(const char * msg, ...){

  if(logd_enable){
    va_list arglist;
    va_start (arglist, msg);
    vprintf(msg,arglist);
    va_end(arglist);
  }
}

static void _log(const char * msg, ...){
  va_list arglist;
  va_start (arglist, msg);
  vprintf(msg,arglist);
  va_end(arglist);
}

#define MAX(X,Y)(X > Y ? X : Y)
#define MIN(X,Y)(X < Y ? X : Y)
#define SIGN(x) (x > 0 ? 1 : (x < 0 ? -1 : 0))

static void * alloc0(size_t size){
  void * ptr = malloc(size);
  memset(ptr, 0, size);
  return ptr;
}

static void * alloc(size_t size){
  return alloc0(size);
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

#define WASM_PAGE_SIZE 64000

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
  WASM_INSTR_CALL_INDIRECT = 0x11,
  WASM_INSTR_DROP = 0x1A,
  WASM_INSTR_SELECT = 0x1B,
  
  WASM_INSTR_LOCAL_GET = 0x20,
  WASM_INSTR_LOCAL_SET = 0x21,
  WASM_INSTR_LOCAL_TEE = 0x22,
  WASM_INSTR_GLOBAL_GET = 0x23,
  WASM_INSTR_GLOBAL_SET = 0x24,
  WASM_INSTR_I32_LOAD = 0x28,
  WASM_INSTR_I64_LOAD = 0x29,
  WASM_INSTR_F32_LOAD = 0x2A,
  WASM_INSTR_F64_LOAD = 0x2B,
  WASM_INSTR_I32_LOAD8_S = 0x2C,
  WASM_INSTR_I32_LOAD8_U = 0x2D,
  WASM_INSTR_I32_LOAD16_S = 0x2E,
  WASM_INSTR_I32_LOAD16_U = 0x2F,
  WASM_INSTR_I64_LOAD8_S = 0x30,
  WASM_INSTR_I64_LOAD8_U = 0x31,
  WASM_INSTR_I64_LOAD16_S = 0x32,
  WASM_INSTR_I64_LOAD16_U = 0x33,
  WASM_INSTR_I64_LOAD32_S = 0x34,
  WASM_INSTR_I64_LOAD32_U = 0x35,
  WASM_INSTR_I32_STORE = 0x36,
  WASM_INSTR_I64_STORE = 0x37,
  WASM_INSTR_F32_STORE = 0x38,
  WASM_INSTR_F64_STORE = 0x39,
  WASM_INSTR_I32_STORE_8 = 0x3A,
  WASM_INSTR_I32_STORE_16 = 0x3B,
  WASM_INSTR_I64_STORE_8 = 0x3C,
  WASM_INSTR_I64_STORE_16 = 0x3D,
  WASM_INSTR_I64_STORE_32 = 0x3E,
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

  WASM_INSTR_I32_TRUNC_F32_S = 0xA8,
  WASM_INSTR_I32_TRUNC_F32_U = 0xA9,
  WASM_INSTR_I32_TRUNC_F64_S = 0xAA,
  WASM_INSTR_I32_TRUNC_F64_U = 0xAB,
  WASM_INSTR_I64_EXTEND_I32_S = 0xAC,
  WASM_INSTR_I64_EXTEND_I32_U = 0xAD,  
  
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
  WASM_BUILTIN_PRINT_STR,
  WASM_BUILTIN_PRINT_F32,
  WASM_BUILTIN_SBRK
}wasm_builtin_fcn;

typedef struct{
  void * code;
  size_t length;
  const char * name;
  const char * module;
  int type;
  u32 argcount;
  u32 retcount;
  // unpack the code for better performance. This is skipped for now.
  //bool resolved; 
  bool import;
  wasm_builtin_fcn builtin;
}wasm_function;

typedef struct{
  int argcount;
  int retcount; // 0 or 1.
}wasm_ftype;

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

  u32 * import_table;
  size_t import_table_count;

  u64 * globals;
  size_t global_count;
  
}wasm_module;

static void wasm_heap_min_capacity(wasm_heap * heap, size_t capacity){
  if(heap->capacity < capacity){
    size_t old_capacity = capacity;
    heap->heap = realloc(heap->heap, capacity);
    memset(heap->heap + old_capacity, 0, capacity - old_capacity);
    heap->capacity = capacity;
  }
}

static void wasm_module_add_func(wasm_module * module){
  module->func_count += 1;
  module->func = realloc(module->func, module->func_count * sizeof(module->func[0]));;
  module->func[module->func_count - 1] = (wasm_function){0};
}

#define OP_NEG(x)-x
#define OP_EQZ(x)x == 0

#define BINARY_OP(type, op){\
  type a = {0}, b = {0};    \
  wasm_pop_##type##_2(ctx, &b, &a);		\
  wasm_push_##type(ctx, a op b);\
  }break;

#define BINARY_OP_U64(type, op){\
  type a = {0}, b = {0};    \
  wasm_pop_##type##_2(ctx, &b, &a);\
  wasm_push_i32(ctx, (i32)(a op b));		\
  }break;


#define BINARY_OPF(type, op){\
  type a = {0}, b = {0};    \
  wasm_pop_##type##_2(ctx, &a, &b);\
  wasm_push_##type(ctx, op(a, b));		\
  }break;


#define UNARY_OPF(type, f){\
  type a = {0};    \
  wasm_pop_##type(ctx, &a);			\
  wasm_push_##type(ctx, f(a));			\
  }break;

#define TRUNCF_I32(X) (i32)(truncf(X))
#define TRUNCF_U32(X) (u32)(truncf(X))
#define TRUNCD_I32(X) (i32)(trunc(X))
#define TRUNCD_U32(X) (u32)(trunc(X))
#define EXTEND_I64_I32(x) (u64)x
#define EXTEND_I64_U32(x) (u64)x

#define UNSUPPORTED_OP(name){ERROR("UNsupported operation\n");}break;

typedef struct{
  u8 * data;
  size_t offset;
  size_t size;
}wasm_code_reader;

static void reader_advance(wasm_code_reader * rd, size_t bytes){
  ASSERT(rd->offset + bytes <= rd->size);
  rd->offset += bytes;
}

static u8 reader_read1(wasm_code_reader * rd){
  u8 b = rd->data[rd->offset];
  reader_advance(rd, 1);
  return b;
}

static void reader_read(wasm_code_reader * rd, void * buffer, size_t len){
  ASSERT(rd->offset + len <= rd->size);
  memcpy(buffer, rd->data + rd->offset, len);
  reader_advance(rd, len);
}

static u64 reader_readu64(wasm_code_reader * rd){
  // read LEB128
  u8 chunk = 0;
  u64 value = 0;
  u32 offset = 0;
  while((chunk = reader_read1(rd)) > 0){
    value |= (0b01111111 & chunk) << offset;
    offset += 7;
    if((0b10000000 & chunk) == false)
      break;
  }
  return value;
}
  
static u32 reader_readu32(wasm_code_reader * rd){
  return reader_readu64(rd);
}

static f32 reader_readf32(wasm_code_reader * rd){
  f32 v = 0;
  memcpy(&v, rd->data + rd->offset, sizeof(v));
  reader_advance(rd, sizeof(v));
  logd("READ f32: %f\n", v);
  return v;
}

static f64 reader_readf64(wasm_code_reader * rd){
  f64 v = 0;
  reader_read(rd, &v, sizeof(v));
  return v;
}

static i64 reader_readi64(wasm_code_reader * rd) {
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

static i32 reader_readi32(wasm_code_reader * rd){
  return (i32)reader_readi64(rd);
}

static size_t reader_getloc(wasm_code_reader * rd){
  return rd->offset;
}
  
static char * reader_readname(wasm_code_reader * rd){
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
  module.heap = heap;
  ASSERT(rd->size > 8);
   
  const char * magic_header_test = "\0asm";
  char magic_header[4];
  reader_read(rd, magic_header, sizeof(magic_header));
  bool contains_magic = memcmp(magic_header_test, magic_header, 4) == 0;
  if(contains_magic == false){
    ERROR("File does not contain correct header");
    return NULL;
  }

  const u8 wasm_version_test[]  = {1,0,0,0};
  char wasm_version[4];
  reader_read(rd, wasm_version, sizeof(wasm_version));
  bool contains_version = memcmp(wasm_version,wasm_version_test, sizeof(wasm_version)) == 0;
  if(contains_version == false){
    ERROR("File does not contain correct header");
    return NULL;
  }
  
  while(rd->offset < rd->size){
    wasm_section section = (wasm_section) reader_read1(rd);
    switch(section){
    case WASM_TYPE_SECTION:
      {
	u32 length = reader_readu32(rd);
	logd("Type section: %i bytes\n", length);
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
    case WASM_CUSTOM_SECTION:
      {
	u32 length = reader_readu32(rd);
	reader_advance(rd,length);
	continue;
      }
    case WASM_IMPORT_SECTION:
      {

	u32 length = reader_readu32(rd);
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
	      f->import = true;
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
	      logd("IMPORT GLOBAL: %s %s %s %i\n", module, name, mut ? "mutable" : "const", type);
	      break;
	    }
	  }
	}
	if(guard + length != reader_getloc(rd))
	  ERROR("Parse imbalance %i != %i + %i (%x)!\n", reader_getloc(rd), guard, length);
	break;
      }
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
    case WASM_FUNCTION_SECTION:
      {
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
	//advance(length);
	break;
      }
    case WASM_START_SECTION:
      {
	ERROR("START Section not supported\n");
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
	u32 length = reader_readu32(rd);
	logd("Code section: length: %i\n", length);
	u32 guard = reader_getloc(rd);
	u32 funccount = reader_readu32(rd);
	logd("Code Count: %i\n", funccount);
	for(u32 i = 0; i < funccount; i++){
	  u32 codesize = reader_readu32(rd);
	  int funcindex = i + module.import_func_count;
	  module.func[funcindex].code = rd->data + rd->offset;
	  module.func[funcindex].length = codesize;
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
	  
	  //printf(" %s\n", module.heap->heap + offset);
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
  wasm_module * r = alloc0(sizeof(module));
  *r = module;
  return r;
}

// everything on the wasm execution stack is a 64bit value.
typedef struct{
  u64 * stack;
  size_t stack_capacity;
  size_t stack_ptr;
  wasm_module * module;
}wasm_execution_context;

static void wasm_push_data(wasm_execution_context * ctx, void * data, size_t size){
  size_t new_size = ctx->stack_ptr + (size + 7) / 8;
  if(new_size > ctx->stack_capacity){
    ctx->stack = realloc(ctx->stack, sizeof(ctx->stack[0]) * (ctx->stack_capacity = (ctx->stack_capacity + 1) * 2));
    logd("increasing stack to %i\n", ctx->stack_capacity);
  }
  if(size < 8)
    memset(ctx->stack + ctx->stack_ptr, 0, sizeof(ctx->stack[0]));
  memmove(ctx->stack + ctx->stack_ptr, data, size);
  ctx->stack_ptr = new_size;
}

static void wasm_push_i32(wasm_execution_context * ctx, i32 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

static void wasm_push_u32(wasm_execution_context * ctx, u32 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

static void wasm_push_u64(wasm_execution_context * ctx, u64 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

static void wasm_push_i64(wasm_execution_context * ctx, i64 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

static void wasm_push_f32(wasm_execution_context * ctx, f32 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

static void wasm_push_f64(wasm_execution_context * ctx, f64 v){
  wasm_push_data(ctx, &v, sizeof(v));
}

static void wasm_pop_data(wasm_execution_context * ctx, void * out){
  ASSERT(ctx->stack_ptr > 0);
  ctx->stack_ptr -= 1;
  memmove(out, ctx->stack + ctx->stack_ptr, 8);
}

static void wasm_pop_data_2(wasm_execution_context * ctx, void * out){
  ASSERT(ctx->stack_ptr > 1);
  ctx->stack_ptr -= 2;
  memmove(out, ctx->stack + ctx->stack_ptr, 8 * 2);
}

static void wasm_stack_drop(wasm_execution_context * ctx){
  ASSERT(ctx->stack_ptr > 0);
  ctx->stack_ptr -= 1;
}

static void wasm_pop_i32(wasm_execution_context * ctx, i32 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = (i32)val;
}

static void wasm_pop_i32_2(wasm_execution_context * ctx, i32 * out, i32 * out2){
  i64 val[2];
  wasm_pop_data_2(ctx, val);
  *out = (i32)(val[1]);
  *out2 = (i32)(val[0]);
}

static void wasm_pop_u32(wasm_execution_context * ctx, u32 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = (u32)val;
}

static void wasm_pop_u32_2(wasm_execution_context * ctx, u32 * out, u32 * out2){
  i64 val[2];
  wasm_pop_data_2(ctx, val);
  *out = (u32)val[1];
  *out2 = (u32)val[0];
}

static void wasm_pop_i64(wasm_execution_context * ctx, i64 * out){
  i64 val;
  wasm_pop_data(ctx, &val);
  *out = val;
}

static void wasm_pop_i64_2(wasm_execution_context * ctx, i64 * out, i64 * out2){
  i64 val[2];
  wasm_pop_data_2(ctx, val);
  *out = val[1];
  *out2 = val[0];
}

static void wasm_pop_u64(wasm_execution_context * ctx, u64 * out){
  wasm_pop_data(ctx, out);
}

static void wasm_pop_u64_2(wasm_execution_context * ctx, u64 * out, u64 * out2){
  u64 val[2];
  wasm_pop_data_2(ctx, val);
  *out = val[1];
  *out2 = val[0];
}

static void wasm_pop2_i64(wasm_execution_context * ctx, i64 * out){
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

static void wasm_pop_f32(wasm_execution_context * ctx, f32 *out){
  union{
    f32 o;
    u64 d;
  }w;
  wasm_pop_data(ctx, &w.d);
  *out = w.o;
}


static void wasm_pop_f32_2(wasm_execution_context * ctx, f32 *out, f32 * out2){
  union{
    f32 o;
    u64 d;
  }w[2];
  wasm_pop_data_2(ctx, &w[0].d);
  *out = w[1].o;
  *out2 = w[0].o;
}

static void wasm_pop_f64(wasm_execution_context * ctx, f64 * out){
  union{
    f64 o;
    u64 d;
  }w;
  wasm_pop_data(ctx, &w.d);
  *out = w.o;
}

static void wasm_pop_f64_2(wasm_execution_context * ctx, f64 * out, f64 * out2){
  union{
    f64 o;
    u64 d;
  }w[2];
  wasm_pop_data_2(ctx, &w[0].d);
  *out = w[1].o;
  *out2 = w[0].o;
}


static void wasm_push_u64r(wasm_execution_context * ctx, u64 * in){
  logd("PUSH u64r: %p\n", *in);
  wasm_push_data(ctx, in, sizeof(in[0]));
}

static void load_op(wasm_code_reader * rd, wasm_execution_context * ctx, int bytes){
  reader_readu32(rd); //align
  u32 offset = reader_readu32(rd);
  i32 addr;
  wasm_pop_i32(ctx, &addr);
  u32 total_offset = addr + offset;
  ASSERT(total_offset + bytes< ctx->module->heap->capacity);
  i64 * valptr = (ctx->module->heap->heap + total_offset);
  wasm_push_data(ctx, valptr, bytes);
}

static void store_op(wasm_code_reader * rd, wasm_execution_context * ctx, int bytes){
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

//awsm VM
void wasm_exec_code(wasm_execution_context * ctx, wasm_code_reader * rd, bool funccall, u32 argcount, u32 retcount){
  wasm_module * mod = ctx->module;
  
  u32 block = 0;
  u32 labels[20] = {0};
  u32 label_return[20] = {0};
  void push_label(){
    labels[block] = rd->offset;
  }
  void pop_label(){
    rd->offset = labels[block];
  }
  UNUSED(pop_label);

  u32 localcount = argcount;
  size_t stack_pos = ctx->stack_ptr - argcount;
  u64 * getlocal(u32 local){
    ASSERT(local < localcount);
    return ctx->stack + stack_pos + local;
  }

  {
    u32 l = funccall ? reader_readu32(rd) : 0;
    for(u32 j = 0; j < l; j++){
      u32 elemcount = reader_readu32(rd);
      u8 type = reader_read1(rd);
      UNUSED(type);
      for(u32 i = 0; i < elemcount; i++){
	wasm_push_u64(ctx, 0);
      }
      localcount += elemcount;
    }
  }
  
  
  while(rd->offset < rd->size){
    wasm_instr instr = reader_read1(rd);
    logd("INSTRUCTION %x: %x\n", rd->offset, instr);
    switch(instr){
    case WASM_INSTR_BLOCK:
      {
	u8 blktype = reader_read1(rd);
	
	block += 1;
	if(blktype != 0x40){
	  u8 blkret = blktype;
	  label_return[block] = blkret;
	}

      }
      break;
    case WASM_INSTR_LOOP:
      {
	logd("LOOP\n");
	u8 blktype = reader_read1(rd);
	
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
	u8 blktype = reader_read1(rd);
	if(blktype != 0x40){
	  u8 blkret = blktype;
	  label_return[block] = blkret;
	}
	u64 cnd;
	wasm_pop_u64(ctx, &cnd);
	if(cnd){
	  logd("ENTER IF %x\n", reader_read1(rd));
	  rd->offset -= 1;
	}else{
	  logd("ENTER ELSE\n");	
	  wasm_instr end = move_to_end_of_block(rd, block);
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
	wasm_instr end = move_to_end_of_block(rd, block);
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
	  goto fcn_end;
	}
	block -= 1;
	logd("END LOOP\n");
      }
      break;
    case WASM_INSTR_BR:
      {
      wasm_instr_br:;
	u32 brindex = reader_readu32(rd);
      next_label:
	//ASSERT(brindex == 0);
	logd("BR: block=%i label=%i index=%i\n", block, labels[block], brindex);
	if(labels[block]){
	  // loop block not sure what brindex does.
	  pop_label();
	  if(brindex > 0)
	    labels[block] = 0;
	}else{
	  logd("BRANCH -> MOVE TO END\n");
	  wasm_instr end = move_to_end_of_block(rd, block);
	  ASSERT(end == WASM_INSTR_END);
	  labels[block] = 0;
	  block -= 1;
	}
	if(brindex > 0){
	  brindex -= 1;
	  goto next_label;
	}
      }
      break;
    case WASM_INSTR_BR_IF:
      {

	u32 x;
	wasm_pop_u32(ctx, &x);
	logd("BR IF %x %i\n", x, block);
	if(x)
	  goto wasm_instr_br;
	reader_readu32(rd);
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
	goto fcn_end;
      }
      break;
    case WASM_INSTR_CALL:
      {
	u32 fcn = reader_read1(rd);
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
	    }else if(nameis("print_f32")){
	      f->builtin = WASM_BUILTIN_PRINT_F32;
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
	    }else if(nameis("sbrk")){
	      f->builtin = WASM_BUILTIN_SBRK;
	    }
	    else{
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
	  case WASM_BUILTIN_PRINT_F32:
	    {
	      f32 v;
	      wasm_pop_f32(ctx, &v);
	      printf("%f", v);
	      break;
	    }
	    break;
	  case WASM_BUILTIN_SBRK:
	    { // malloc support
	      i32 v;
	      wasm_pop_i32(ctx, &v);
	      logd("SBRK(%i)\n",v);
	      mod->heap->heap = realloc(mod->heap->heap, mod->heap->capacity += v);
	      wasm_push_u32(ctx,  mod->heap->capacity);
	      break;
	    }
	  default:
	    ERROR("UNKNOWN BUILTIN COMMAND\n");
	  }
	  
	}else{
	  
	  logd("CALL %s (%i)\n",f->name, fcn);
	  u32 stackpos = ctx->stack_ptr;
	  wasm_code_reader rd = {.data = f->code, .size = f->length, .offset = 0};
	  wasm_exec_code(ctx, &rd, true, f->argcount, f->retcount);
	  if(stackpos - f->argcount + f->retcount != ctx->stack_ptr){
	    ERROR("Stack imbalance! stk:%i  args:%i ret:%i newstk:%i\n", stackpos, f->argcount, f->retcount, ctx->stack_ptr);
	  }

	  
	  u64 v;
	  if(ctx->stack_ptr > 0 && f->retcount == 1){
	    wasm_pop_u64(ctx, &v);
	    wasm_push_u64(ctx, v);
	    logd("RETURNED %s %i \n", f->name, v);
	  }

	  //printf("return..\n");
	}

      }
      break;
    case WASM_INSTR_CALL_INDIRECT:
      {
	/*u32 ind =*/ reader_readu32(rd);
	u32 fcn;
	wasm_pop_u32(ctx, &fcn);
	if(fcn >= mod->import_table_count){
	  ERROR("Invalid indirect call: %i\n", fcn);
	}
	fcn = mod->import_table[fcn];
	wasm_function * f = mod->func + fcn;
	logd("CALL INDIRECT %s (%i)\n", f->name, fcn);
	if(f->import) ERROR("Cannot indirectly call builtin\n");
	wasm_code_reader rd = {.data = f->code, .size = f->length, .offset = 0};
	wasm_exec_code(ctx, &rd, true, f->argcount, f->retcount);
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
	u64 result = (s != 0) ? x : y;
	//printf("SELECT RESULT %p\n", result);
	wasm_push_u64(ctx, result);
      }
      break;
      
    case WASM_INSTR_LOCAL_SET:
      {
	u32 local = reader_readu32(rd);
	ASSERT(local < localcount);
	logd("Local set: %i\n", local);
	wasm_pop_u64(ctx, getlocal(local));
	break;
      }
    case WASM_INSTR_LOCAL_GET:
      {
	u32 local = reader_readu32(rd);
	ASSERT(local < localcount);
	wasm_push_u64r(ctx, getlocal(local));
	logd("Local get %i: %p\n", local, getlocal(local)[0]);
	break;
      }
    case WASM_INSTR_LOCAL_TEE:
      {
	u32 local = reader_readu32(rd);
	ASSERT(local < localcount);
	u64 value;
	wasm_pop_u64(ctx, &value);
	wasm_push_u64(ctx, value);	
	getlocal(local)[0] = value;
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
      load_op(rd, ctx, 4);
      break;
    case WASM_INSTR_I64_LOAD:
      load_op(rd, ctx, 8);
      break;
    case WASM_INSTR_F32_LOAD:
      load_op(rd, ctx, 4);
      break;
    case WASM_INSTR_F64_LOAD:
      load_op(rd, ctx, 8);
      break;
    case WASM_INSTR_I32_CONST:
      wasm_push_i32(ctx, reader_readi32(rd));
      break;
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
      store_op(rd, ctx, 6);break;
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
	size_t cap = mod->heap->capacity;
	wasm_push_u64(ctx, cap / WASM_PAGE_SIZE);
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
	logd("New memory size: %p\n", newsize);
      }
      break;
    case WASM_INSTR_I64_CONST:
      wasm_push_i64(ctx, reader_readi64(rd)); break;
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
      {
	i64 a = {0};
	wasm_pop_i64(ctx, &a);
	wasm_push_i64(ctx, a);
      }
      break;
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
    default:
      ERROR("Cannot execute opcode %x\n", instr);
      break;
    }
  }

 fcn_end:;
  
  u64 return_value = 0;
  if(retcount == 1)
    wasm_pop_u64(ctx, &return_value);
  
  for(u32 i = 0; i < localcount; i++){
    wasm_stack_drop(ctx);
  }
  if(retcount == 1){
    wasm_push_u64(ctx, return_value);
  }
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

  logd_enable = diagnostic;
  
  size_t buffer_size = 0;
  void * data = read_file_to_buffer(file, &buffer_size);
  wasm_heap heap = {0};
  wasm_code_reader rd = {.data = data, .size = buffer_size, .offset = 0};
  wasm_module * mod = load_wasm_module(&heap, &rd);
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
    wasm_code_reader rd = {.data = some_code, .size = sizeof(some_code), .offset = 0};
    wasm_exec_code(&ctx, &rd, false, 0, 0);
  }

  return 0;

 print_help:
  printf("Usage: awsm [file] [entrypoint] [--diagnostic] \n");
  return 1;
}
