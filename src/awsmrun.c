#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <awsm.h>
int main(int argc, char ** argv){

  char * file = NULL;
  char * entrypoint = NULL;
  bool diagnostic = false;
  for(int i = 1; i < argc; i++){
    if(strcmp(argv[i], "--diagnostic") == 0){
      diagnostic = true;
      continue;
    }
    if(file == NULL)
      file = argv[i];
    else if(entrypoint == NULL)
      entrypoint = argv[i];
  }
  
  awsm_log_diagnostic = diagnostic;
  wasm_module * mod = awsm_load_module_from_file(file);

  if(awsm_load_thread(mod, entrypoint) == false){
    printf("Unable to load thread");
    return 1;
  }
  
  while(awsm_process(mod, 200)){
  }
  return 0;
}
