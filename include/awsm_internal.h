typedef int8_t i8;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef float f32;
typedef double f64;

#define WASM_PAGE_SIZE 64000

// This controls how many steps are executed in each fork context before switching.
#define AWSM_DEFAULT_STEPS_PER_CONTEXT_SWITCH 20

typedef enum WASM_SECTION{
  WASM_CUSTOM_SECTION = 0,
  WASM_TYPE_SECTION = 1,
  WASM_IMPORT_SECTION = 2,
  WASM_FUNCTION_SECTION = 3,
  WASM_TABLE_SECTION = 4,
  WASM_MEMORY_SECTION = 5,
  WASM_GLOBAL_SECTION = 6,
  WASM_EXPORT_SECTION = 7,
  WASM_START_SECTION = 8,
  WASM_ELEMENT_SECTION = 9,
  WASM_CODE_SECTION = 10,
  WASM_DATA_SECTION = 11
}wasm_section;

typedef enum WASM_TYPE{
  WASM_TYPE_BLOCK_EMPTY = 0x40,
  WASM_TYPE_F64 = 0x7C,
  WASM_TYPE_F32 = 0x7D,
  WASM_TYPE_I64 = 0x7E,
  WASM_TYPE_I32 = 0x7F
}wasm_type;

typedef enum WASM_IMPORT_TYPE{
  WASM_IMPORT_FUNC = 0,
  WASM_IMPORT_TABLE = 1,
  WASM_IMPORT_MEM = 2,
  WASM_IMPORT_GLOBAL =3
}wasm_import_type;


typedef enum WASM_FUNCTION_TYPE{
  WASM_FUNCTION_TYPE_IMPORT = 2,
}wasm_function_type;

typedef struct{
  void * code;
  size_t length;
  const char * name;
  const char * module;
  int type;
  u32 argcount;
  u32 retcount;
  wasm_function_type functype;
  size_t code_offset;
}wasm_function;

typedef struct{
  int argcount;
  int retcount; // 0 or 1.
}wasm_ftype;

typedef struct{
  void * heap;
  size_t capacity;
}wasm_heap;

struct _wasm_module{
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
  u32 global_count;

  wasm_execution_stack ** stacks;
  u32 stack_count;

  u64 steps_per_context_switch;
  u64 steps_executed;

  u64 current_stack;

  // debug
  breakcheck_callback * breakcheck;
  void ** breakcheck_context;
  size_t breakcheck_count;
  bool enabled_breakchecks;
  u8 * dwarf_debug_lines;
  size_t dwarf_debug_lines_size;

  // user data
  void * user_data;
  
};



typedef struct{
  i32 block;
  u32 label_offset;
  u32 stack_pos;
  u32 localcount;
  u32 retcount;
  int func_id;
  //u32 argcount;
  wasm_code_reader rd;
}wasm_control_stack_frame;

typedef struct{
  u32 type;
  u32 offset;
}wasm_label;

// everything on the wasm execution stack is a 64bit value.
struct _wasm_execution_stack{
  u64 * stack;
  u32 stack_capacity;
  u32 stack_ptr;
  
  wasm_control_stack_frame * frames;
  u32 frame_capacity;
  u32 frame_ptr;

  wasm_label * labels;
  u32 label_capacity;
    
  wasm_module * module;

  void * initializer;
  u32 initializer_size;
  bool complex_state;
  bool yield;
  bool keep_alive;
  
  char * error;
};

void wasm_fork_stack(wasm_execution_stack * ctx);

// debug

typedef struct{
  u32 column, line, address, op_index, prev_line;
  
  bool prologue_end, is_stmt;
  
  bool default_is_stmt;
  u8 minimum_instr_length;
  u8 maxmium_ops_per_instr;
  i8 line_base;
  u8 line_range;
  u32 file;

  const u8 * files;
  
}dwarf_debug_line_state_machine;

bool breakcheck_enabled(wasm_execution_stack * ctx);
void breakcheck_run(wasm_execution_stack * ctx);
int dwarf_source_location(u8 * dwarf_code, u32 code_size, u32 code_offset, char * out_filename, int * out_line);


// utils
#define UNUSED(x) (void)(x)
#define MAX(X,Y)(X > Y ? X : Y)
#define MIN(X,Y)(X < Y ? X : Y)
#define SIGN(x) (x > 0 ? 1 : (x < 0 ? -1 : 0))
void (*_error)(const char * file, int line, const char * msg, ...);
#define log _log
#define ERROR(msg,...) if(_error) _error(__FILE__,__LINE__,msg, ##__VA_ARGS__)
#define ASSERT(expr) if(__builtin_expect(!(expr), 0)){ERROR("Assertion '" #expr "' Failed");}
void logd(const char * msg, ...);
