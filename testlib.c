//compile with clang: clang-9 --target=wasm32 -nostdlib -Wl,--export-all -Wl,--no-entry -O3 -Wl,-no-gc-sections testlib2.c -Wl,--allow-undefined  -o testlib3.wasm 
// asd
// asd
// asd
// asd
void * get_symbol(const char * module, const char * symbol, unsigned int argcount, unsigned int retcount);

int print_str(const char * x);
void print_i32(int x);
void print_f32(float x);
//void print_f64(double x);
void require_i32(int x, int y);
int awsm_fork();
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
  print_i32(fib(5));
  print_str("\ncalc!\n");
}

int main(){
  print_str("Hello World 0!\n");
  print_str("Hello World 1!\n");
  print_str("Hello World 2!\n");
  print_str("Hello World 3!\n");
  //subthing();
  //asd
  subthing();
  return 0;
}





void _main(){
  print_str("Hello World!");
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
    print_i32(fib(17));
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
