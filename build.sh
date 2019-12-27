
#clang-9 -O0 --target=wasm32 -emit-llvm ./ -o libstdlib2.bc 
clang-9 -O0 --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all stdlib2.c ./testlib2.c -o testlib2.wasm -v
