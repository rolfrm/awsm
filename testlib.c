#include <stdlib.h>
#include <string.h>
extern int print_str(const char * x);
void print_i32(int val);
void require_i32(int expected, int actual);
void require_i64(long long expected, long long actual);
int myvalue = 100;
char * globthing = "hellohello";
void fail(){
  require_i32(1,0);
}
int add_things(int x, int y){
  
  int it = 10;
  
  for(int i = 0; i < 5; i++)
    print_i32(i);
  while(1){
    print_i32(it);
    it += 1;
  }
  return x + y + myvalue - 3 + (int) it;
}


int add_things2(int x, int y){
  int cnst = 10;
  for(int i = 0; i < 3; i++)
    print_i32(i + cnst);
  return x - y + cnst;
}

int fib(int n){
  if(n <2)
    return 1;
  return fib(n - 1) + fib(n - 2);
}

void test_math(int five, int seven){
  require_i32(5, five);
  require_i32(-5, -five);
  require_i32(7, seven);
  require_i32(-7, -seven);
  require_i32(5 + 7, five + seven);
  require_i32(5 - 7, five - seven);
  require_i32(5 * 7, five * seven);
  require_i32(5 / 7, five / seven);
  require_i32(5 % 7, five % seven);
  require_i32(7 % 5, seven % five);
  require_i32(5 & 7, five & seven);
  require_i32(5 | 7, five | seven);
  require_i32(5 ^ 7, five ^ seven);
  require_i32(5 << 7, five << seven);
  require_i32((5 * 5 * 5 * 5) >> 7, (five * five * five * five) >> seven);
  require_i32(8, fib(five));
  require_i32(13, fib(6));
  require_i32(21, fib(seven));
  require_i32(233, fib(seven + five));
}


void test_math_i64(long long five, long long seven){
  require_i32(5, five);
  require_i32(-5, -five);
  require_i32(7, seven);
  require_i32(-7, -seven);
  require_i32(5 + 7, five + seven);
  require_i32(5 - 7, five - seven);
  require_i32(5 * 7, five * seven);
  require_i32(5 / 7, five / seven);
  require_i32(5 % 7, five % seven);
  require_i32(7 % 5, seven % five);
  require_i32(5 & 7, five & seven);
  require_i32(5 | 7, five | seven);
  require_i32(5 ^ 7, five ^ seven);
  require_i32(5 << 7, five << seven);
  require_i32((5 * 5 * 5 * 5) >> 7, (five * five * five * five) >> seven);
  require_i32(8, fib(five));
  require_i32(13, fib(6));
  require_i32(21, fib(seven));
  require_i32(233, fib(seven + five));
}



int main(){
  //add_things2(6, 5);
  print_str("\"Hello World!\"\n");
  test_math(5, 7);
  print_str("TEST MATH I64\n\n\n");
  test_math_i64(5, 7);
  //add_things(3, 4);
  //megaprinter3(add_things(6, 5));
  return 0;
}

