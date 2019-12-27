#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <stdarg.h>
#include <signal.h>
#include <dlfcn.h>

typedef enum{
  TEST_A,
  TEST_B,
  TEST_C,
}TEST_ENUM;

const char * test_enum_names[] = {"A", "B"};

static void * alloc0(size_t size){
  void * ptr = malloc(size);
  memset(ptr, 0, size);
  return ptr;
}

static void * alloc(size_t size){
  return alloc0(size);
}

static void * read_stream_to_buffer(FILE * f, size_t * size){
  if(f == NULL)
    return NULL;
  fseek(f,0,SEEK_END);
  *size = ftell(f);
  char * buffer = alloc0(*size + 1);
  fseek(f, 0, SEEK_SET);
  size_t l = fread(buffer,*size,1,f);
  //ASSERT(l == 1);
  return buffer;
}

static void * read_file_to_buffer(const char * filepath, size_t * size){
  FILE * f = fopen(filepath, "r");
  if(f == NULL) return NULL;
  char * data = read_stream_to_buffer(f, size);
  fclose(f);
  return data;
}

void process_file(char * file, void (* process)(char * name, int opcode)){
  FILE * f = fopen(file, "r");
  char * buffer = alloc0(100);
  size_t buffer_size = 100;
  int opcode;
  int scanned_invalid = 0;
  int scanned = 0;
  while((scanned_invalid = fscanf(f, "#%s\n",buffer)) >0 || (scanned = fscanf(f, "%s %x\n",buffer, &opcode))>0 || (scanned_invalid = fscanf(f, "%s\n",buffer)) >0){
    if(scanned != 2 || scanned_invalid){
      if(scanned_invalid){
	//printf("%s ", buffer);
	getline(&buffer, &buffer_size, f);
      }
      scanned_invalid = 0;
      scanned = 0;
      //printf("%s", buffer);
    }else{
      process(buffer, opcode);
      //printf("Scanned: %s 0x%x\n", buffer, opcode);
    }
  }
  fclose(f);
  free(buffer);
}

char * clone_string(char *  str){
  int len = strlen(str);
  char * copy = malloc(len + 1);
  strcpy(copy, str);
  return copy; 
}

void format_as_enum(char * name, int opcode){
  printf("  WASM_INSTR_%s = 0x%x,\n", name, opcode);
}

char ** opcode_names = NULL;
int opcode_count = 0;

void opcode_name(char * name, int opcode){
  if(opcode >= opcode_count){
    opcode_names = realloc(opcode_names, sizeof(opcode_names[0]) * (opcode + 1));
    for(int i = opcode_count; i <= opcode; i++)
      opcode_names[i] = NULL;
    opcode_count = opcode + 1;
  }
  opcode_names[opcode] = clone_string(name);
}

int main(int argc, char ** argv){
  if(argc != 2)
    return 1;
  char * file = argv[1];
  printf("typedef enum WASM_INSTR{\n");
  process_file(file, format_as_enum);
  printf("}wasm_instr;\n");
  process_file(file, opcode_name);
  printf("__attribute__((unused)) static const char * wasm_instr_name[] = {\n");
  for(int i = 0; i < opcode_count; i++){
    char * name = opcode_names[i];
    if(name == NULL){
      printf("  NULL, //reserved\n");
    }else{
      printf("  \"%s\",\n", name);
    }
  }
  printf("};\n");
  printf("__attribute__((unused)) static int wasm_instr_count = %i;\n", opcode_count);
  
  return 0;

}
