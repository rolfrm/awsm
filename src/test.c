#include <iron/full.h>
#include "wasm_instr.h"
#include <awsm.h>
#include <stdarg.h>
#include <signal.h>


static u64 reader_readu64(u8 * buf){
  // read LEB128
  u8 chunk = 0;
  u64 value = 0;
  u64 offset = 0;
  while((chunk = *buf) > 0){
    value |= (0b01111111L & chunk) << offset;
    offset += 7;
    if((u64)(0b10000000L & chunk) == false)
      break;
    buf += 1;
  }
  return value;
}

static void encode_u64_leb(u64 value, u8 * buffer){
  while(true){
    
    *buffer = value & 0b01111111L;
    value >>= 7;
    if(value)
      *buffer |= 0b10000000L;
    else break;
    buffer += 1;
  }
}

bool test_value(u64 value){
  u8 buffer[16] = {0};
  encode_u64_leb(value, buffer);
  u64 result = reader_readu64(buffer);
  printf("%p == %p\n", result, value);
  if(result != value){
    printf("%p == %p\n", result, value);
    return false;
  }
  return true;

}
void _error(const char * file, int line, const char * msg, ...){
  UNUSED(file);UNUSED(line);UNUSED(msg);
  char buffer[1000];  
  va_list arglist;
  va_start (arglist, msg);
  vsprintf(buffer,msg,arglist);
  va_end(arglist);
  printf("%s\n", buffer);
  printf("Got error at %s line %i\n", file,line);
  raise(SIGINT);
}


int main(int argc, char ** argv){
  UNUSED(argc);
  UNUSED(argv);

  for(u64 i = 0 ;i < 64; i++){
    printf(":%i\n", i);
    if(!test_value((u64)1 << i | i << (i / 2)))
      return 1;
  }

  //awsm_log_diagnostic = diagnostic;
  wasm_module * mod = awsm_load_module_from_file("./testlib3.wasm");
  ASSERT(mod != NULL);
  int idx = awsm_get_function(mod, "main");
  printf("mod: %i %i\n", mod, idx);
  awsm_log_diagnostic = true;
  u8 code[] = {0, WASM_INSTR_I64_CONST, 5, WASM_INSTR_END};
  awsm_define_function(mod, "p5", code, sizeof(code), 1, 0);
  wasm_execution_stack * trd = awsm_load_thread(mod, "p5");
  wasm_execution_stack_keep_alive(trd, true);
  awsm_push_i64(trd, 10);
  i64 v2 = awsm_pop_i64(trd);
  ASSERT(v2 == 10);
  awsm_process(mod, 10);
  i64 v = awsm_pop_i64(trd);
  printf("Result: %i\n", v);
  ASSERT(v == 5);

  
  return 0;
  /*
  wasm_execution_stack * ctx = alloc0(sizeof(ctx[0]));
  char * file = NULL;
  char * entrypoint = NULL;
  bool diagnostic = false;
  bool test = false;
  for(int i = 1; i < argc; i++){
    if(strcmp(argv[i], "--diagnostic") == 0){
      diagnostic = true;
      continue;
    }
    if(strcmp(argv[i], "--test") == 0){
      test = true;
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
  wasm_module * mod = awsm_load_module_from_file(file);
  wasm_module_add_stack(mod, ctx);
  
  if(!test){
    int main_index = func_index(mod, entrypoint);
    if(main_index == -1){
      log("Unable to lookup function '%s'\n", entrypoint);
      return 1;
    }
    logd("Executing... %i\n", main_index);
    u8 code[] = {WASM_INSTR_I32_CONST, 0, WASM_INSTR_I32_CONST, 0, WASM_INSTR_CALL, (u8) main_index};
    
    wasm_load_code(ctx, code, sizeof(code));

    while(awsm_process(mod, mod->steps_per_context_switch * 20)){
    }
    
  }else{
    {
      logd("TEST CONST\n");
      u8 code[] = {WASM_INSTR_I32_CONST, 4};
      wasm_exec_code3(ctx, code, sizeof(code), 1);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 4);
      ASSERT(ctx->frames[0].block == 0);
    } 
if(false){
      u8 code[] = {WASM_INSTR_I32_CONST, 30, WASM_INSTR_I32_CONST, 4, WASM_INSTR_I32_CONST, 8, WASM_INSTR_I32_ADD};
      wasm_exec_code3(ctx, code, sizeof(code), 3000);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 12);
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 30);
    }
    {
      logd(" -- TEST LOOP -- \n");
      u8 code[] = {WASM_INSTR_I32_CONST, 13, WASM_INSTR_LOOP, 0, WASM_INSTR_BR, 0, WASM_INSTR_END};
      wasm_exec_code3(ctx, code, sizeof(code), 20);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 13);
      ASSERT(ctx->frames[0].block > 0); // this frame never completes
    }
    {
      logd(" -- TEST BLOCK -- \n");
      u8 code[] = {WASM_INSTR_I32_CONST, 15, WASM_INSTR_BLOCK, 0, WASM_INSTR_BR, 0, WASM_INSTR_END};
      wasm_exec_code3(ctx, code, sizeof(code), 20);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 15);
      ASSERT(ctx->frames[0].block == 0);
    }
    {
      logd(" -- TEST IF -- \n");
      u8 code[] = {WASM_INSTR_I32_CONST, 1, WASM_INSTR_IF, 0, WASM_INSTR_I32_CONST, 23, WASM_INSTR_ELSE, WASM_INSTR_I32_CONST, 24,  WASM_INSTR_END};
      wasm_exec_code3(ctx, code, sizeof(code), 20);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 23);
      ASSERT(ctx->frames[0].block == 0);
      
      code[1] = 0;
      wasm_exec_code3(ctx, code, sizeof(code), 40);
      wasm_pop_i32(ctx, &r);
      printf("R: %i\n", r);
      ASSERT(r == 24);
      ASSERT(ctx->frames[0].block == 0);
    }
    if(false){
      logd(" -- TEST RETURN -- \n");
      u8 code[] = {WASM_INSTR_I32_CONST, 9, WASM_INSTR_I32_CONST, 15, WASM_INSTR_BLOCK, WASM_TYPE_I32, WASM_INSTR_RETURN, WASM_INSTR_END};
      wasm_exec_code3(ctx, code, sizeof(code), 20);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 9);
      ASSERT(ctx->frames[0].block == 0);
      ASSERT(ctx->frame_ptr == 0);
    }
    { // call
      logd(" -- TEST FUNCTION -- %i \n", func_index(mod, "add"));
      u8 code[] = {WASM_INSTR_I32_CONST, 13, WASM_INSTR_I32_CONST, 15, WASM_INSTR_CALL, func_index(mod, "add")};
      wasm_exec_code3(ctx, code, sizeof(code), 2000);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 28);
      ASSERT(ctx->frames[0].block == 0);
      ASSERT(ctx->frame_ptr == 0);
    }
    { // call
      logd(" -- TEST FUNCTION -- %i \n", func_index(mod, "fib"));
      u8 code[] = {WASM_INSTR_I32_CONST, 12, WASM_INSTR_CALL, func_index(mod, "fib")};
      int executed_steps = wasm_exec_code3(ctx, code, sizeof(code), 2000000);
      i32 r;
      wasm_pop_i32(ctx, &r);
      logd("fib(15): %i  steps: %i\n", r, executed_steps);
      ASSERT(r == 233);
      ASSERT(ctx->frames[0].block == 0);
      ASSERT(ctx->frame_ptr == 0);
    }
    

    if(false){ // call
      logd(" -- TEST MAIN FUNCTION -- \n");
      int main_index = func_index(mod, "main");
      if(main_index == -1){
	ERROR("MAIN NOT FOUND\n");
      }
      u8 code[] = {WASM_INSTR_I32_CONST, 13, WASM_INSTR_I32_CONST, 15, WASM_INSTR_CALL, main_index};
      wasm_exec_code3(ctx, code, sizeof(code), 2100000);
      i32 r;
      wasm_pop_i32(ctx, &r);
      ASSERT(r == 0); // main returns 0
      ASSERT(ctx->frames[0].block == 0);

    }
  }
  return 0;

 print_help:
  printf("Usage: awsm [file] [entrypoint] [--diagnostic] \n");
  return 1;*/

}
