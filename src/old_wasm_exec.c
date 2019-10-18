
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
      switch(type){
      case WASM_TYPE_F64:
      case WASM_TYPE_F32:
      case WASM_TYPE_I32:
      case WASM_TYPE_I64:
	break;
      default:
	ERROR("Unsupported type\n");
      }
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
      pop_label(ctx, false);
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
	u64 result = (s != 0) ? x : y;
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
