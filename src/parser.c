#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <microio.h>
#include "utils.h"
#include "lisp.h"

void * clone(const void * ptr, size_t size){
  void * heapptr = malloc(size);
  memcpy(heapptr, ptr, size);
  return heapptr;
}

lisp_value new_cons(lisp_value car, lisp_value cdr){
  cons consv = {.car = car, .cdr = cdr, .refcount = 1};
  cons * heap = clone(&consv, sizeof(consv));
  return (lisp_value){.cons = heap, .type = LISP_CONS};
}

// like new_cons, but marks the code location as well.
lisp_value new_cons_r(io_reader * rd, lisp_value a, lisp_value b){
  UNUSED(rd);
  lisp_value newcons = new_cons(a, b);
  return newcons;
}

void skip_comment_and_whitespace(io_reader * rd){
  while(true){
	 uint8_t c = io_peek_u8(rd);
	 if(c == ' ' || c == '\n' || c == '\t'){
		io_read_u8(rd);
	 }
	 else if(c == ';'){
		while(true){
		  c = io_read_u8(rd);
		  if( c == '\n')
			 break;
		  if(c == 0)
			 break;
		}
	 }else{
		break;
	 }
  }
}

lisp_value read_token_string(io_reader * rd){
  
  io_writer wd = {0};
  io_read_u8(rd); // skip first quote.
  while(true){
	 uint8_t c = io_read_u8(rd);
    if(c == '\\'){
      var c2 = io_peek_u8(rd);
      if(c2 == 'n'){
        io_read_u8(rd);
        c = '\n';
      }else{
        c = io_read_u8(rd);
      }
    }else if(c == '"'){
		c = io_peek_u8(rd);
		if(c == '"'){
        io_read_u8(rd);
        // double quote
		  io_write_u8(&wd, c);
		}else{
		  break;
		}
	 }
	 else  if(c == 0)
		break;// incomplete string.
	 io_write_u8(&wd, c);
  }
  io_write_u8(&wd, 0);
  lisp_value v = string_lisp_value(wd.data);
  io_writer_clear(&wd);
  return v;
}

lisp_value parse_token(const char * x, int count){

  char * tp = NULL;

  {
	 printf("INTEGR? %s\n", x);
		
	 int64_t o = strtoll(x, &tp, 10);
	 if(tp == x + count){
		return integer_lisp_value(o);
	  
	 }
  }
  
  {
	 double o = strtold(x, &tp);
	 if(tp == x + count)
		return rational_lisp_value(o);
  }
  
  // otherwise it is a symbol
  return symbol_lisp_value(get_symbol_id(x));
}


lisp_value read_token_data(io_reader * rd){
  uint8_t c = io_peek_u8(rd);
  if(c == '"'){
	 return read_token_string(rd);
  }
  io_writer wd = {0};
  while(true){
	 c = io_peek_u8(rd);
	 if(c == ' ' || c == ')' || c == '(' || c == '\t' || c == 0 || c == '\n'){
		break;
	 }
	 io_read_u8(rd);
	 io_write_u8(&wd, c);
  }
  io_write_u8(&wd, 0);
  lisp_value vv = parse_token(wd.data, wd.offset - 1);
  io_writer_clear(&wd);
  return vv;
}

i64 list_count(lisp_value list){
  i64 i = 0;
  while(!is_nil(list)){
	 i++;
	 list = cdr(list);
  }
  return i;
}

lisp_value reverse(lisp_value list){
  i64 cnt = list_count(list);
  if(cnt <= 1)
	 return list;
  lisp_value * items = malloc(sizeof(lisp_value) * cnt);

  for(i64 i = 0; i < cnt; i++){
	 items[i] = car(list);
	 list = cdr(list);
  }
  lisp_value v = nil;
  for(i64 i = 0; i < cnt; i++){
	 v = new_cons(items[i], v);
  }
  free(items);
  return v;
}

lisp_value tokenize_stream(io_reader * rd){
  skip_comment_and_whitespace(rd);
  uint8_t c = io_peek_u8(rd);
  if(c == 0) return nil;
  if(c == ':'){
    var symbol = read_token_data(rd);
    return symbol;
  }
  if(c == '\''){
	 io_read_u8(rd);
  	 var c = new_cons_r(rd, quote_sym, new_cons_r(rd,tokenize_stream(rd), nil));
    
    return c;
  }
  if(c == '`'){
	 io_read_u8(rd);
	 return new_cons_r(rd, quasiquote_sym, new_cons_r(rd,tokenize_stream(rd), nil));
  }
  if(c == ','){
	 io_read_u8(rd);
	 if(io_peek_u8(rd) == '@'){
		io_read_u8(rd);
		return new_cons_r(rd, unquote_splice_sym, new_cons_r(rd,tokenize_stream(rd), nil));
	 }
	 return new_cons_r(rd, unquote_sym, new_cons_r(rd,tokenize_stream(rd), nil));
  }
  if(c == '('){
	 io_read_u8(rd);

	 skip_comment_and_whitespace(rd);
	 if(io_peek_u8(rd) == ')'){
		io_read_u8(rd);
		return nil;
	 }
	 lisp_value head = nil;
	 while(true){
		var v = tokenize_stream(rd);
		var new = new_cons_r(rd, v, nil);
		if(is_nil(head)){
		  head = new;
		}else{
		  // leak
		  head = new_cons(car(new), head);
		}
		skip_comment_and_whitespace(rd);
		uint8_t c = io_peek_u8(rd);
		if(c == 0 || c == ')'){
		  io_read_u8(rd);
		  break;
		}
		if(c == '.'){
		  var save = *rd;
		  io_read_u8(rd);
		  var loc = io_getloc(rd);
		  skip_comment_and_whitespace(rd);
		  var nextloc = io_getloc(rd);
		  if(loc == nextloc){
			 *rd = save;
		  }else{
			 var v = tokenize_stream(rd);
			 
			 head = new_cons(v, head);
			 
			 skip_comment_and_whitespace(rd);
			 if(io_read_u8(rd) != ')'){
				raise_string("Unexpected token");
			 }
			 break;
		  }

		}
	 }
	 return reverse(head);
	 
  }else{
	 skip_comment_and_whitespace(rd);
	 return read_token_data(rd);
  }
}


lisp_value lisp_read_stream(io_reader * rd){
  return tokenize_stream(rd);
}

lisp_value lisp_read_string(const char * str){

  io_reader w = io_reader_from_bytes((void *)str, strlen(str) + 1);
  w.offset = 0;
  return lisp_read_stream(&w);
}
