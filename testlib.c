#include <stdlib.h>
#include <string.h>
extern int print(const char * x);
int print2(const char * x);
void print3(int val);
int myvalue = 100;
char * globthing = "hellohello";
int add_things(int x, int y){
  
  int it = 10;
  
  for(int i = 0; i < 5; i++)
    print3(i);
  while(1){
    print3(it);
    it += 1;
  }
  return x + y + myvalue - 3 + (int) it;
}


int add_things2(int x, int y){
  int cnst = 10;
  for(int i = 0; i < 3; i++)
    print3(i + cnst);
  return x + y + cnst;
}


int main(){
  add_things2(6, 5);
  print("\"Hello World!\"\n");
  //add_things(3, 4);
  //megaprinter3(add_things(6, 5));
  return 0;
}

