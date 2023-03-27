#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <microio.h>
#include "utils.h"
#include "lisp.h"
#include "wasm_instr.h"
#include "awsm.h"
#include "awsm_internal.h"

// pattern matching based statically compiled language
// (+ 1 2)
// + -> match arguments, like i64 or fixnum.
// when the argument types are known use the fixed implementation
// when the argument types are not known, use runtime dynamic dispatch.

lisp_value integer_lisp_value(i64 v){
  return (lisp_value){.integer = v, .type = LISP_INTEGER};
}
lisp_value symbol_lisp_value(i64 v){
  return (lisp_value){.integer = v, .type = LISP_SYMBOL};
}
lisp_value rational_lisp_value(f64 v){
  return (lisp_value){.rational = v, .type = LISP_RATIONAL};
}

void * clone(const void * data, size_t count);

lisp_value string_lisp_value(const char * str0){
  lisp_string str = {.refcount = 1, .data = clone(str0, strlen(str0) + 1) };
  return (lisp_value){.string = clone(&str, sizeof(str)), .type = LISP_STRING};
}
void raise_string(const char * strerror){
  UNUSED(strerror);
}
lisp_value car(lisp_value v){
  if(v.type == LISP_CONS){
	 return v.cons->car;
  }
  return nil;
}
lisp_value cdr(lisp_value v){
  if(v.type == LISP_CONS){
	 return v.cons->cdr;
  }
  return nil;
}
bool is_nil(lisp_value v){
  return v.type == LISP_NIL;
}
void (* _error)(const char * file, int line, const char * msg, ...);
lisp_value unquote_sym, quote_sym, unquote_splice_sym, quasiquote_sym;
const lisp_value nil = {0};
i64 get_symbol_id(const char * symname){
  UNUSED(symname);
  return 10;
}

typedef struct __wasm_builder{
  io_writer wd;
  lisp_value code;

}wasm_builder;

void emit(wasm_builder * b, u8 opcode){
  io_write_u8(&b->wd, opcode);
}

void emit_i64c(wasm_builder * b, u8 opcode, i64 constant){
  io_write_u8(&b->wd, opcode);
  io_write_i64_leb(&b->wd, constant);
}

lisp_value get_arg(wasm_builder * b, int index) {
  lisp_value v = b->code;
  while(index > 0){
	 index -= 1;
	 v = cdr(v);
  }
  return car(v);
}

bool add_gen1(wasm_builder * b){
  lisp_value arg1 = get_arg(b, 1);
  if(arg1.type != LISP_INTEGER){
	 return false;
  }
  lisp_value arg2 = get_arg(b, 2);
  if(arg2.type != LISP_INTEGER)
	 return false;
  emit_i64c(b, WASM_INSTR_I64_CONST, arg1.integer);
  emit_i64c(b, WASM_INSTR_I64_CONST, arg2.integer);
  emit(b, WASM_INSTR_I64_ADD);
  return true;
}

void println(lisp_value v){
  switch(v.type){
  case LISP_NIL: printf("()");break;
  case LISP_CONS: printf("(");
	 {
		lisp_value it = v;
		while(!is_nil(it)){
		  println(car(it));
		  it = cdr(it);
		  if(!is_nil(it))
			 printf(" ");
		}
		printf(")");
	 }

	 break;
  case LISP_INTEGER: printf("%i", v.integer);break;
  case LISP_RATIONAL: printf("%f", v.rational);break;
  case LISP_SYMBOL: printf("sym%i", v.integer);break;
  case LISP_STRING: printf("%s", v.string->data);break;
	 
  }

}

int main(){
  lisp_value v = lisp_read_string("(+ 1 2)");
  println(v);
  printf("\n");
  wasm_builder b = {.code = v, .wd = {0}};
  bool x = add_gen1(&b);
  wasm_module * mod = awsm_load_dynamic_module();
  u8 code[] = {0, WASM_INSTR_I64_CONST, 55, WASM_INSTR_I64_CONST, 55, WASM_INSTR_I64_ADD, WASM_INSTR_NOP,WASM_INSTR_NOP,WASM_INSTR_NOP,WASM_INSTR_NOP};

  u64 g1 = awsm_new_global(mod);
  i64 * x2 = awsm_global_ptr(mod, g1);
  *x2 = 1000;

  u64 g2 = awsm_new_global(mod);
  x2 = awsm_global_ptr(mod, g2);
  *x2 = 130000;
  
  
  io_writer cwriter = {0};
  io_write_u8(&cwriter, 0);
  io_write_u8(&cwriter, WASM_INSTR_GLOBAL_GET);
  io_write_u64_leb(&cwriter, g1);
  io_write_u8(&cwriter, WASM_INSTR_GLOBAL_GET);
  io_write_u64_leb(&cwriter, g2);
  io_write_u8(&cwriter, WASM_INSTR_I64_ADD);
  

  
  int helloId = awsm_define_function(mod, "hello", code, 1, 0 ,0);
  int helloId2 = awsm_define_function(mod, "hello2", cwriter.data, cwriter.offset, 0 ,0);
  printf("id: %i %i\n", helloId, helloId2);
  wasm_execution_stack * stack = awsm_load_thread(mod, "hello2");
  stack->keep_alive = true;
  awsm_process(mod, 10);
  printf("T: %i %i %i \n", v.type, x, stack->stack[1]);UNUSED(mod);
  UNUSED(stack);
  
  UNUSED(v);
  return 0;
}
