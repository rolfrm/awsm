# AWSM - A WebAssembly Bytecode Interpreter

**Status** Testing...

**Goal** Be able to host itself.


## Getting Started

**Compile libawsm.so**

```sh
>> make release
```

** Compile wasm executor** 

```sh
make -f makefile.awsmrun
```

**Compile test library**

```sh
>> clang-9 --target=wasm32 -nostdlib -Wl,--export-all -Wl,--no-entry -O3 -Wl,-no-gc-sections testlib.c -Wl,--allow-undefined  -o testlib.wasm 
```

**Run**

```sh
>> ./awsm testlib.wasm main
"Hello World!"

```

## Getting started using it as a library

Compile libawsm.so the following way.

``sh
>> make release
``

C header files can be found in the ```include``` folder.

An example of a program using the library can look like this:
```c
//clang main.c -lawsm -o main
#include <stdint.h>
#include <stdbool.h>
#include <awsm.h>

int main(){
   wasm_module * mod = awsm_load_module_from_file("testmodule.wasm"); // Load the module
   awsm_load_thread(mod, "go"); // start the a thread from the 'main' function.
   while(awsm_process(mod, 1024)){} // Iterate 1024 steps at a time!
   return 0;
}
```

testmodule.c could look like this:
```c
//clang --target=wasm32 -nostdlib -Wl,--export-all -Wl,--no-entry -O3 -Wl,-no-gc-sections testmodule.c -Wl,--allow-undefined -o testmodule.wasm 
void print_str(const char * str); // utility function from libawsm.
void go(){
     print_str("hello world!\n");
}

```

To run it:

```sh
>>./main
hello world!
```

A more complete example, see https://github.com/rolfrm/awsm-game

## Performance

After a bit of tuning: ~350M instructions/s. Will do a more accurate measurement at a later point.

- -O3 has an performance improvement of a factor two over -O2.
- -O2 has an perfromance improvement of a factor 5 over -O0.

Overall surprised that it performs at this level.
