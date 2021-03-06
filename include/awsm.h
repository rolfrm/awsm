typedef int8_t i8;
typedef int32_t i32;
typedef int64_t i64;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef float f32;
typedef double f64;


typedef struct _wasm_module wasm_module;
typedef struct _wasm_execution_stack wasm_execution_stack;


// basic interface
wasm_module * awsm_load_module_from_file(const char * wasm_file);
bool awsm_process(wasm_module * module, uint64_t steps_total);
wasm_execution_stack * awsm_load_thread(wasm_module * module, const char * func);
wasm_execution_stack * awsm_load_thread_arg(wasm_module * module, const char * func, uint32_t arg);

void awsm_set_error_callback(void (*f)(const char * file, int line, const char * msg, ...));

void awsm_register_function(wasm_module * module, void (* func)(wasm_execution_stack * stack), const char * name);

typedef enum {
  AWSM_FCN_OPT_NONE = 0,
  AWSM_FCN_OPT_BLOCKING = 1
}awsm_fcn_opt;

typedef enum {
  // return immediately
  AWSM_BLK_RETURN = 16,
  // yield the thread
  AWSM_BLK_YIELD = 32,
  // select() on a number of fd's. with a timeout
  // u32 count, [int fds], u32 timeout
  AWSM_BLK_SELECT = 64
}awsm_blk_status;

void awsm_register_function2(wasm_module * module, void (* func)(wasm_execution_stack * stack), const char * name, awsm_fcn_opt options);

void awsm_push_i32(wasm_execution_stack * s, int32_t v);
void awsm_push_i64(wasm_execution_stack * s, int64_t v);
void awsm_push_u32(wasm_execution_stack * s, uint32_t v);
void awsm_push_u64(wasm_execution_stack * s, uint64_t v);
void awsm_push_f32(wasm_execution_stack * s, float v);
void awsm_push_f64(wasm_execution_stack * s, double v);
void awsm_push_ptr(wasm_execution_stack * ctx, void * ptr);

int32_t awsm_pop_i32(wasm_execution_stack * s);
int64_t awsm_pop_i64(wasm_execution_stack * s);
uint32_t awsm_pop_u32(wasm_execution_stack * s);
uint64_t awsm_pop_u64(wasm_execution_stack * s);
float awsm_pop_f32(wasm_execution_stack * s);
double awsm_pop_f64(wasm_execution_stack * s);
void * awsm_pop_ptr(wasm_execution_stack * s);

// default false;
extern bool awsm_log_diagnostic;
void awsm_diagnostic(bool diagnostic_level_enabled);


int awsm_get_function(wasm_module * module, const char * name);
int awsm_get_function_ret_cnt(wasm_module * module, int id);
int awsm_get_function_arg_cnt(wasm_module * module, int id);

int awsm_define_function(wasm_module * module, const char * name, void * len, size_t l, int retcnt, int argcnt);
void wasm_execution_stack_keep_alive(wasm_execution_stack * trd, bool keep_alive);
void awsm_thread_keep_alive(wasm_execution_stack * s, int keep_alive);
size_t awsm_new_global(wasm_module * module);
void * awsm_module_heap_ptr(wasm_module * mod);
size_t awsm_heap_size(wasm_module * mod);
void awsm_heap_increase(wasm_module * mod, size_t amount);
wasm_module * awsm_stack_module(wasm_execution_stack * s);
void awsm_module_set_user_data(wasm_module * mod, void * ptr);
void * awsm_module_get_user_data(wasm_module * mod);

// save/load VM state
void awsm_module_load(io_reader * rd, wasm_module * mod);
void awsm_module_save(io_writer * wd, wasm_module * mod);
void awsm_module_save_state(wasm_module * mod, void ** buffer, size_t * size);
void awsm_module_load_state(wasm_module * mod, void * buffer, size_t size);

// Debugging API
typedef void (* breakcheck_callback)(wasm_execution_stack * stl, void * user_context);
void * awsm_debug_stack_ptr(wasm_module * mod, uint64_t * size);
int awsm_debug_next_instr(wasm_execution_stack * stk);
typedef int breakcheck_id;
breakcheck_id awsm_debug_attach_breakcheck(wasm_module * mod, breakcheck_callback f, void * user_context);
void awsm_debug_remove_breakcheck(wasm_module * mod, breakcheck_id id);
const char * awsm_debug_instr_name(int instr);
int awsm_debug_location(wasm_execution_stack * ctx);
const char * awsm_debug_current_function(wasm_execution_stack * ctx);
int awsm_debug_source_location(wasm_execution_stack * ctx, char * out_filename, int * out_line);
int awsm_debug_source_address(wasm_execution_stack * ctx);
