//compile with clang: clang-9 --target=wasm32 -nostdlib -Wl,--export-all -Wl,--no-entry -O3 -Wl,-no-gc-sections testlib2.c -Wl,--allow-undefined  -o testlib3.wasm 

void * get_symbol(const char * module, const char * symbol, unsigned int argcount, unsigned int retcount);

int print_str(const char * x);
void print_i32(int x);
void print_f32(float x);
//void print_f64(double x);
void require_i32(int x, int y);
int awsm_fork();
unsigned long long new_coroutine(void (* f)(void * arg), void * arg);

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

void test_print(){
  print_str("test?\n");

}

void test_load_symbol(){
  get_symbol("libglfw.so", "glfwCreateWindow", 4, 1);
}

void test_load_symbol1(void * arg){
  test_print();
  print_str("done\n");
}
void (*testthing)(void * a);
void test_new_coroutine(){
  if(testthing == 0) testthing = test_load_symbol1;
  
  //new_coroutine(main_forked, 0);
  test_load_symbol1(0);//testthing(0);
  //new_coroutine(test_load_symbol1, 0);
  //new_coroutine(awsm_fork, 0);
  print_str("???\n");
}

void test_new_coroutine2(){
  if(testthing == 0) testthing = test_load_symbol1;
  
  //new_coroutine(main_forked, 0);
  testthing(0);
  //new_coroutine(test_load_symbol1, 0);
  //new_coroutine(awsm_fork, 0);
  print_str("???\n");
}
