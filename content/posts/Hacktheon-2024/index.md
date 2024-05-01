---
title: "Hacktheon 2024: Account"
description: "Hacktheon 2024: Account"
summary: "Hacktheon 2024: Account writeup"
categories: ["Writeup"]
tags: ["Pwnable"]
#externalUrl: ""
date: 2024-05-02
draft: true
authors:
  - Shin24
---

Vừa rồi mình cùng team `Weebpwn` đã tham gia giải Hacktheon 2024 ở bảng Advanced và kết thúc với thứ hạng **#7**

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/33388f3d-99d0-4b5f-846b-7ffbb207dbea)

Đề web của giải khá dễ và gần như không có gì đáng nói, ở mảng pwn thì còn 1 bài khá tốn thời gian reverse là `Account`, sau giải thì mình quyết định ngồi giải lại bài này vì nghe bạn mình nói nó custom lại allocator riêng và cần reverse lại nghe khá hay.

## Reversing

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

