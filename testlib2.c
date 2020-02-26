//compile with clang: clang-9 --target=wasm32 -nostdlib -Wl,--export-all -Wl,--no-entry -O3 -Wl,-no-gc-sections testlib2.c -Wl,--allow-undefined  -o testlib3.wasm 

void * get_symbol(const char * module, const char * symbol, unsigned int argcount, unsigned int retcount);

typedef long long i64;
typedef unsigned char u8;

i64 get_heap_size();
void set_heap_size(i64 newsize);

i64 heap_start = 0;
i64 heap_end = 0;

void init_alloc(){
  static int alloc_inited = 0;
  if(alloc_inited == 0){
    alloc_inited = 1;
    heap_start = get_heap_size();
    heap_end = heap_start + 128000;
    set_heap_size(heap_end);
  }
}

void resize_heap(i64 bytes){
  if(bytes > heap_end - heap_start){
    set_heap_size(bytes + heap_start);
    heap_end = bytes + heap_start;
  }
}

void * _alloc(int bytes){
  init_alloc();
  static i64 alloc_offset = -1;
  if(alloc_offset == -1){
    alloc_offset = heap_start;
  }
  void * ptr = (void *) alloc_offset;
  alloc_offset += bytes;
  if(alloc_offset > heap_end)
    resize_heap((heap_start - heap_end) * 2);

  return ptr;
}

void * alloc(int bytes){
  return _alloc(bytes);

}

int print_str(const char * x);
void print_i32(int x);
void print_f32(float x);
//void print_f64(double x);
void require_i32(int x, int y);
int awsm_fork();
unsigned long long new_coroutine(void (* f)(void * arg), void * arg);
void yield();
int fib(int n){
  //print_i32(n);
  if(n <2)
    return 1;
  return fib(n - 1) + fib(n - 2);
}

void inscribe(char * x){
  x[0] = 'a';
  x[1] = '\n';
}
float x, y2;
void incr_y(){
  y2 += 0.1;
  print_f32(y2);
}

void test_fork(){
  //int forkid = awsm_fork();
  //print_i32(forkid);
  if(awsm_fork()){
   print_str("fork\n");
 }else{
   print_str("other fork\n");
 }
}

typedef struct{
  float x, y;
}vec2;

vec2 vec2_new(float x, float y){
  return (vec2){.x = x, .y = y};
}

void vec2_print(vec2 v){
  print_str("("); 
  print_f32(v.x);
  print_str(",");
  print_f32(v.y);
  print_str(")"); 
}

void subthing(){
  print_i32(fib(15));
  print_str("\ncalc!\n");
}

int main(){
  print_str("Hello World!\n");
  return 0;
}

int test_main(){
  vec2 v = vec2_new(1.0, -1.5);
  float x = 0;
  for(float y = 0.2; y < 5; y*=2){
    x += y + y2;
    y2 = y2 + 0.01;
  }
  print_f32(y2);
  print_str(" ");
  print_f32(x);
  print_str("\n");
  
  subthing();
  
  require_i32(987, fib(15));
  return 5;
}

void main_forked(){
  if(awsm_fork()){
    awsm_fork();
    main();
  }else{
    print_i32(fib(15));
    print_str("\n");
    if(awsm_fork()){
      main();
    }else{
      print_str("main ends\n");
    }
  }  
}

struct {
  i64 * a;
  i64 * b;
  u8 * type;

  i64 count;
  i64 end;
  
}cons;

typedef enum{
  TYPE_NIL = 0,
  TYPE_I64 = 1,
  TYPE_F64 = 2,
  TYPE_CONS = 3
}etype;

i64 mknil(){ return 0; }

i64 mkcons(i64 a, i64 b){
  i64 c = (i64)cons.end;
  cons.end += 1;
  cons.a[c] = a;
  cons.b[c] = b;
  return c << 2 | TYPE_CONS;
}

i64 mki64(i64 a){
  return a << 2 | TYPE_I64;
}

i64 unmki64(i64 a){
  return a >> 2;
}

int consp(i64 a){
  return (a & 0b11) == TYPE_CONS;
}

int integerp(i64 a){
  return (a & 0b11) == TYPE_I64;
}

i64 cdr(i64 a){
  return cons.b[a >> 2];
}

i64 car (i64 a){
  return cons.a[a >> 2];
}

i64 cons_type(i64 a){
  return cons.type[a >> 2];
}

i64 conslen(i64 a){
  i64 c = 0;
  while(consp(a)){
    c += 1;
    a = cdr(a);
  }
  return c;
}

i64 add1(i64 a, i64 b){
  return mki64(unmki64(a) + unmki64(b));
}

void test_print(){
  print_str("test?\n");
  i64 * a = alloc(sizeof(i64) * 1024);
  i64 * b = alloc(sizeof(i64) * 1024);
  long long s = get_heap_size();
  print_i32(s);
  print_str("\n");
  print_i32((int)a);
  print_str("\n");
  print_i32((int)b);
  print_str("\n");
  print_str("heap?\n");

  print_i32(a[5]);
  print_str("\n");
  print_i32(b[5]);
  print_str("\n");
  print_i32(sizeof(i64));
  print_str("\n");

  cons.a = a;
  cons.b = b;
  cons.type = alloc(sizeof(u8) * 1024);
  cons.count = 1024;

  i64 v1 = mki64(53);
  i64 v2 = mki64(10);
  i64 c = mkcons(v1, v2);
  i64 c2 = mkcons(v1, c);
  i64 c3 = mkcons(v1, c2);
  print_i32(v1); print_str(" ");  print_i32(v2); print_str(" ");  print_i32(c); print_str("\n");
  print_i32(c2); print_str("\n");
  print_i32(conslen(c3)); print_str("\n");
  print_i32(unmki64(v1)); print_str("\n");
  print_i32(integerp(v1)); print_str("\n");
  print_i32(integerp(c2)); print_str("\n");
  print_i32(consp(c2)); print_str("\n");
}

void test_load_symbol(){
  get_symbol("libglfw.so", "glfwCreateWindow", 4, 1);
}

void test_load_symbol1(void * arg){
  test_print();
  print_i32((int) arg);
  print_str("done 1\n");
  yield();
  print_str("done 2\n");
  yield();
  print_str("done 3\n");
      
}
void (*testthing)(void * a);
void test_new_coroutine(){
  if(testthing == 0) testthing = test_load_symbol1;
  
  for(int i = 0 ; i < 50; i++)
    new_coroutine(test_load_symbol1, (void*)i);
  print_str("done first thread\n");
}

void test_new_coroutine2(){
  if(testthing == 0) testthing = test_load_symbol1;
  
  //new_coroutine(main_forked, 0);
  testthing(0);
  //new_coroutine(test_load_symbol1, 0);
  //new_coroutine(awsm_fork, 0);
  print_str("???\n");
}
