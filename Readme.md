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

**Performance** After a bit of tuning: ~350M instructions/s. Will do a more accurate measurement at a later point.

- -O3 has an performance improvement of a factor two over -O2.
- -O2 has an perfromance improvement of a factor 5 over -O0.

Overall surprised that it performs at this level.
