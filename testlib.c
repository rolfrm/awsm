#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
extern int print_str(const char * x);
void print_i32(int val);
void print_i64(long long val, long long val2);
void require_i32(int expected, int actual);
void require_i64(long long expected, long long actual);
void require_f32(float expected, float actual);
void require_f64(double expected, double actual);
int myvalue = 100;
char * globthing = "hellohello";
void fail(){
  require_i32(1,0);
}

typedef long long i64;

int add_things(int x, int y){
  
  int it = 10;
  
  for(int i = 0; i < 5; i++)
    print_i32(i);
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

int add(int x, int y){
  return x + y;
}

i64 addi64(i64 x, i64 y){
  return x + y;
}


void test_math(int five, int seven){
  require_i32(5, five);
  require_i32(-5, -five);
  require_i32(7, seven);
  require_i32(-7, -seven);
  require_i32(5 + 7, add(five, seven));
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
  require_i64(5, five);
  require_i64(-5, -five);
  require_i64(7, seven);
  require_i64(-7, -seven);
  require_i64(5 + 7, five + seven);
  require_i32(5 + 7, addi64(five, seven));
  require_i64(5 - 7, five - seven);
  require_i64(5 * 7, five * seven);
  require_i64(5 / 7, five / seven);
  require_i64(5 % 7, five % seven);
  require_i64(7 % 5, seven % five);
  require_i64(5 & 7, five & seven);
  require_i64(5 | 7, five | seven);
  require_i64(5 ^ 7, five ^ seven);
  require_i64(5 << 7, five << seven);
  require_i64((5 * 5 * 5 * 5) >> 7, (five * five * five * five) >> seven);
}


void test_math_f32(float five, float seven){
  require_f32(5, five);
  require_f32(-5, -five);
  require_f32(7, seven);
  require_f32(-7, -seven);
  require_f32(5 + 7, five + seven);
  require_f32(5 - 7, five - seven);
  require_f32(5 * 7, five * seven);
  require_f32(5.f / 7.f, five / seven);
}


void test_math_f64(double five, double seven){
  require_f64(5, five);
  require_f64(-5, -five);
  require_f64(7, seven);
  require_f64(-7, -seven);
  require_f64(5 + 7, five + seven);
  require_f64(5 - 7, five - seven);
  require_f64(5 * 7, five * seven);
  require_f64(5.0 / 7.0, five / seven);
}
typedef struct{
  float x,y;
}vec2;

vec2 vec2_new(float x, float y){
  return (vec2){.x = x, .y = y};
}
 

vec2 vec2_add(vec2 a, vec2 *b){
  a.x += b->x;
  a.y += b->y;
  return a;
}

int main(){

  print_str("\"Hello World!\"\n");

  add_things2(6, 5); 
  print_str("\"Lets run some tests!!\"\n\n");
  test_math(5, 7);
  print_str("\nTEST MATH I64\n\n");

  test_math_i64(5L, 7L);


  print_str("\nTEST MATH F32\n\n");
  test_math_f32(5.0f, 7.0f);
  
  print_str("\nTEST MATH F64\n\n");
  test_math_f64(5.0, 7.0);

  print_str("\nMore Stuff\n\n");
  srand(1234321);
  print_i32(rand());
  print_i32(rand());
  add_things(1,2);

  vec2 z = vec2_new(4,5);
  vec2 y = vec2_new(7,8);
  vec2 x = vec2_add(z, &y);
  require_f32(11.0f, x.x);
  require_f32(13.0f, x.y);

  
  return 0;
}

// this test function uses syscall 4 to print "Hello World!".
void test2(){
  char * str = "Hello World!\n";
  write(0, str, strlen(str));
}

void hello_world(){
  print_str("Kello World!\n");
}

typedef struct{
  int fd;
  char * str;
  int count;
}call4arg;

int __syscall4(int which, call4arg * argptr){
  return print_str(argptr->str);
}
