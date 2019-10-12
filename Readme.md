# AWSM - A Simple WebAssembly Bytecode Interpreter

**Status** Hello World!

**Goal** Be able to host itself.


**Step 1** Compile awsm
```sh
>> make
```

**Step 2** Compile test library

```sh
>> emcc ./testlib.c -Os -o testlib.wasm -s EXPORT_ALL=1 -s ERROR_ON_UNDEFINED_SYMBOLS=0
```

**Step 3** Run

```sh
>> ./awsm testlib.wasm main
"Hello World!"

```