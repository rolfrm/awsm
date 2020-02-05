//compile with clang: clang-9 --target=wasm32 -nostdlib -Wl,--export-all -Wl,--no-entry -O3 -Wl,-no-gc-sections testlib2.c -Wl,--allow-undefined  -o testlib3.wasm 


int print_str(const char * x);
void print_i32(int x);
void print_f32(float x);
void print_f64(double x);
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

int main(){

  /*char  a[10];
  inscribe(a);
  print_str(a);
  print_str("!!! ");
  print_i32(fib(10));
  print_str("\n");
  print_str("!!!!! ");
  print_f64(1.0);
  print_str("\n");*/
  float x = 0;
  for(float y = 0.2; y < 5; y*=2){
    x += y + y2;
    y2 = y2 + 0.01;
  }
  print_f32(y2);
  print_str(" ");
  print_f32(x);
  print_str("\n");
  
  print_f32(x);
  print_str("\n");
  print_str("pre fork:");
  print_i32(fib(15));
  print_str("\n");
  print_i32(fib(15));
  print_str("\n");
  print_i32(fib(15));
  print_str("\n");
  
  if(awsm_fork()){
    awsm_fork();
    //print_i32(fib(15));
    print_str("I am forked\n");

  }else{
    print_str("I am not forked\n");
  }

  print_i32(fib(15));
  print_str("\n");

  /*while(1){
    a[0] += 1;
    }*/

  return 5;
}

void _start(){

}
