typedef struct _wasm_module wasm_module;
typedef struct _wasm_execution_stack wasm_execution_stack;


// basic interface
wasm_module * awsm_load_module_from_file(const char * wasm_file);
bool awsm_process(wasm_module * module, uint64_t steps_total);
wasm_execution_stack * awsm_load_thread(wasm_module * module, const char * func);

void awsm_set_error_callback(void (*f)(const char * file, int line, const char * msg, ...));

void awsm_register_function(wasm_module * module, void (* func)(wasm_execution_stack * stack), const char * name);

void awsm_push_i32(wasm_execution_stack * s, int32_t v);
void awsm_push_i64(wasm_execution_stack * s, int64_t v);
void awsm_push_u32(wasm_execution_stack * s, uint32_t v);
void awsm_push_u64(wasm_execution_stack * s, uint64_t v);
void awsm_push_f32(wasm_execution_stack * s, float v);
void awsm_push_f64(wasm_execution_stack * s, double v);

int32_t awsm_pop_i32(wasm_execution_stack * s);
int64_t awsm_pop_i64(wasm_execution_stack * s);
uint32_t awsm_pop_u32(wasm_execution_stack * s);
uint64_t awsm_pop_u64(wasm_execution_stack * s);
float awsm_pop_f32(wasm_execution_stack * s);
double awsm_pop_f64(wasm_execution_stack * s);
void * awsm_pop_ptr(wasm_execution_stack * s);

// default false;
extern bool awsm_log_diagnostic;



int awsm_get_function(wasm_module * module, const char * name);
int awsm_define_function(wasm_module * module, const char * name, void * len, size_t l, int retcnt, int argcnt);
void wasm_execution_stack_keep_alive(wasm_execution_stack * trd, bool keep_alive);
