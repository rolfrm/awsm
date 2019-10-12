#include <stdlib.h>
#include <string.h>
extern int print(const char * x);
int print2(const char * x);
void print3(int val);
int myvalue = 100;
char * globthing = "hellohello";
int add_things(int x, int y){
  
  int ptr = 10;
  /*  if(x > y)
    ptr = 1;
  else
    ptr = 2;
  for(int i = 0; i < myvalue; i++){
    ptr += i;
    }*/
  
  for(int i = 0; i < 5; i++)
    print3(i);
  while(1)
    print3(ptr);  
  return x + y + myvalue - 3 + (int) ptr;
}


int add_things2(int x, int y){
  int ptr = 10;
  for(int i = 0; i < 3; i++)
    print3(ptr);
  return x + y + ptr;
}


int main(){
  add_things2(6, 5);
  print("\"Hello World!\"\n");
  //megaprinter3(add_things(6, 5));
  return 0;
}

