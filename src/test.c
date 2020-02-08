
int main(int argc, char ** argv){

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
  return 1;
}
