
typedef struct __lisp_value lisp_value;
typedef struct __cons cons;
typedef struct __lisp_string lisp_string;
typedef struct __list_vector lisp_vector;
typedef struct __lisp_function lisp_function;
typedef enum {
  LISP_NIL,
  LISP_CONS,
  LISP_INTEGER,
  LISP_RATIONAL,
  LISP_SYMBOL,
  LISP_STRING,
  //LISP_FUNCTION
}lisp_type;

struct __lisp_value
{
  lisp_type type;
  union{
	 cons * cons;
	 i64 integer;
	 f64 rational;
	 lisp_string * string;
	 lisp_function * function;
  };
};

struct __cons {
  i64 refcount;
  const lisp_value car;
  const lisp_value cdr;
};

struct __lisp_string {
  i64 refcount;
  char * data;
};

struct __lisp_function {
  lisp_type * argument_types;
  size_t argument_count;
  lisp_type return_type;

};

lisp_value integer_lisp_value(i64 v);
lisp_value symbol_lisp_value(i64 id);
lisp_value rational_lisp_value(f64 id);
lisp_value string_lisp_value(const char * str);
void raise_string(const char * strerror);
lisp_value car(lisp_value v);
lisp_value cdr(lisp_value v);
bool is_nil(lisp_value v);
extern lisp_value unquote_sym, quote_sym, unquote_splice_sym, quasiquote_sym;
extern const lisp_value nil;
i64 get_symbol_id(const char * symname);
lisp_value lisp_read_string(const char * str);
