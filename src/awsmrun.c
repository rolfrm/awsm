#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <awsm.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)
static void _error(const char * file, int line, const char * msg, ...){
  UNUSED(file);UNUSED(line);UNUSED(msg);
  char buffer[1000];  
  va_list arglist;
  va_start (arglist, msg);
  vsprintf(buffer,msg,arglist);
  va_end(arglist);
  printf("%s\n", buffer);
  printf("Got error at %s line %i\n", file,line);
  raise(SIGINT);
}
int lastline = -1;
void print_at_break(wasm_execution_stack * stk, void * ctx){
  UNUSED(ctx);
  int instr = awsm_debug_next_instr(stk);
  const char * currentf = awsm_debug_current_function(stk);
  UNUSED(currentf);
  UNUSED(instr);
  //printf("%s %i %s\n", awsm_debug_instr_name(instr), awsm_debug_location(stk), currentf);
  char filename[100] = {0};
  int line = 0;
  int err = awsm_debug_source_location(stk, filename, &line);
  
  if(err == 0){
    if(line == 0)
      return;
    if(line == lastline)
       return;
    lastline = line;

    char filename2[100];
    sprintf(filename2, "./%s", filename);
    
    FILE * fp = fopen(filename2, "r");
    if(fp != NULL){
      char * linebuf = NULL;

      for(int i = 0; i < line-1; i++){
	size_t len = 0;
	getline(&linebuf, &len, fp);
      }
      for(int i = 0; i < 1; i++){
	size_t len = 0;
	if(getline(&linebuf, &len, fp) != -1){
	  linebuf[strlen(linebuf) - 1] = 0;
	  printf("%s:%i   %s %s", filename, line, linebuf, i == 1 ? "<----" :"");
	}
      }
      free(linebuf);
      fclose(fp);
      getchar();
    }
    


    
  }else{
    printf("Cannot read line data (%i)\n", err);  
  }
}

void read_file_to_buffer(const char * file, void ** buffer, size_t * size){
  FILE *f = fopen(file, "rb");
  if(f == NULL) {
    *size = 0;
    return;
  }
  fseek(f, 0, SEEK_END);
  size_t fsize = ftell(f);
  fseek(f, 0, SEEK_SET);  /* same as rewind(f); */
  
  *buffer = malloc(fsize + 1);
  fread(*buffer, 1, fsize, f);
  fclose(f);
  *size = fsize;
}

void read_some(void * data, u64 count, void * ptr){
  FILE * f = ptr;
  fread(data, count, 1, f);
}


void write_some(void * data, u64 count, void * ptr){
  FILE * f = ptr;
  fwrite(data, count, 1, f);
}
int main(int argc, char ** argv){
  awsm_set_error_callback(_error);
  char * file = NULL;
  char * entrypoint = NULL;
  bool diagnostic = false;
  bool debug = false;
  bool partial = false;
  for(int i = 1; i < argc; i++){
    if(strcmp(argv[i], "--diagnostic") == 0){
      diagnostic = true;
      continue;
    }
    if(strcmp(argv[i], "--debug") == 0){
      debug = true;
      continue;
    }
    if(strcmp(argv[i], "--partial") == 0){
      partial = true;
      continue;
    }
    if(file == NULL)
      file = argv[i];
    else if(entrypoint == NULL)
      entrypoint = argv[i];
  }
  
  awsm_log_diagnostic = diagnostic;
  wasm_module * mod = awsm_load_module_from_file(file);
  if(debug){
    awsm_debug_attach_breakcheck(mod, print_at_break, NULL);
    
  }

  if(awsm_load_thread(mod, entrypoint) == false){
    printf("Unable to load thread");
    return 1;
  }
  if(partial){
    

    FILE * f = fopen("partial.dump", "r");
    if(f != NULL){
      data_reader rd = {. f= read_some, .user_data = f};
      awsm_module_load(&rd, mod);
      fclose(f);
    }
    
    if(awsm_process(mod, 10)){
      remove("partial.dump");
      FILE * f = fopen("partial.dump", "w");
      data_writer rd = {. f= write_some, .user_data = f};
      awsm_module_save(&rd, mod);
      fclose(f);
    }else{
      remove("partial.dump");
    }
    return 0;
  }
  while(awsm_process(mod, 200)){
  }
  return 0;
}
