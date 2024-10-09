---
title: "CIS 2024: Ollala"
description: "CIS 2024: Ollala"
summary: "CIS 2024: Ollala writeup"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-10-09
draft: false
authors:
  - Shin24
---

Đây là bài cuối trong giải CIS 2024 do anh Jang ra, sau giải mình có ngồi giải lại và đây là writeup của mình cho bài này

## Background

Context bài này anh Jang dùng lại một CVE đã có PoC của ollama, nhưng server đã được hardening bằng cách ollama không được chạy với quyền root, do đó không thể đơn giản ghi đè `/etc/ld.so.preload` được

## Solution
### CVE-2024-47561

Với CVE này ta có thể đọc/ghi một file bất kì, tuy nhiên ta chưa biết được là nên ghi file nào để RCE, sẽ khá dễ để biết được là trong `/tmp` có một folder chứa các shared object file

![image](https://github.com/user-attachments/assets/1cdd9c88-5c89-4962-88fb-0a4cdf2fefb9)

![image](https://github.com/user-attachments/assets/edfa166e-b374-4766-983a-afc910679665)

Nếu check thử mem map của process ollama sẽ thấy chưa có shared object nào trong số đó được load vào cả

```
ollama@815da42fbefa:/$ cat /proc/`pidof ollama serve`/maps
00400000-00402000 r--p 00000000 08:20 33561260                           /usr/local/ollama
00402000-00ebd000 r-xp 00002000 08:20 33561260                           /usr/local/ollama
00ebd000-11ca6000 r--p 00abd000 08:20 33561260                           /usr/local/ollama
11ca6000-11ca7000 r--p 118a5000 08:20 33561260                           /usr/local/ollama
11ca7000-11d38000 rw-p 118a6000 08:20 33561260                           /usr/local/ollama
11d38000-11db2000 rw-p 00000000 00:00 0 
13234000-13255000 rw-p 00000000 00:00 0                                  [heap]
c000000000-c000c00000 rw-p 00000000 00:00 0 
c000c00000-c004000000 ---p 00000000 00:00 0 
7f0538000000-7f0538021000 rw-p 00000000 00:00 0 
7f0538021000-7f053c000000 ---p 00000000 00:00 0 
7f053c000000-7f053c021000 rw-p 00000000 00:00 0 
7f053c021000-7f0540000000 ---p 00000000 00:00 0 
7f0540000000-7f0540021000 rw-p 00000000 00:00 0 
7f0540021000-7f0544000000 ---p 00000000 00:00 0 
7f05477ff000-7f0547800000 ---p 00000000 00:00 0 
7f0547800000-7f0548000000 rw-p 00000000 00:00 0 
7f0548000000-7f0548021000 rw-p 00000000 00:00 0 
7f0548021000-7f054c000000 ---p 00000000 00:00 0 
7f054c000000-7f054c021000 rw-p 00000000 00:00 0 
7f054c021000-7f0550000000 ---p 00000000 00:00 0 
7f0550000000-7f0550021000 rw-p 00000000 00:00 0 
7f0550021000-7f0554000000 ---p 00000000 00:00 0 
7f0554000000-7f0554021000 rw-p 00000000 00:00 0 
7f0554021000-7f0558000000 ---p 00000000 00:00 0 
7f0558000000-7f0558021000 rw-p 00000000 00:00 0 
7f0558021000-7f055c000000 ---p 00000000 00:00 0 
7f055c7f9000-7f055c7fa000 ---p 00000000 00:00 0 
7f055c7fa000-7f055cffa000 rw-p 00000000 00:00 0 
7f055cffa000-7f055cffb000 ---p 00000000 00:00 0 
7f055cffb000-7f055d7fb000 rw-p 00000000 00:00 0 
7f055d7fb000-7f055d7fc000 ---p 00000000 00:00 0 
7f055d7fc000-7f055dffc000 rw-p 00000000 00:00 0 
7f055dffc000-7f055dffd000 ---p 00000000 00:00 0 
7f055dffd000-7f055e7fd000 rw-p 00000000 00:00 0 
7f055e7fd000-7f055e7fe000 ---p 00000000 00:00 0 
7f055e7fe000-7f055effe000 rw-p 00000000 00:00 0 
7f055effe000-7f055efff000 ---p 00000000 00:00 0 
7f055efff000-7f055f7ff000 rw-p 00000000 00:00 0 
7f055f7ff000-7f055f800000 ---p 00000000 00:00 0 
7f055f800000-7f0560000000 rw-p 00000000 00:00 0 
7f0560000000-7f0560021000 rw-p 00000000 00:00 0 
7f0560021000-7f0564000000 ---p 00000000 00:00 0 
7f0564000000-7f0564021000 rw-p 00000000 00:00 0 
7f0564021000-7f0568000000 ---p 00000000 00:00 0 
7f0568000000-7f0568021000 rw-p 00000000 00:00 0 
7f0568021000-7f056c000000 ---p 00000000 00:00 0 
7f056c000000-7f056c021000 rw-p 00000000 00:00 0 
7f056c021000-7f0570000000 ---p 00000000 00:00 0 
7f0570000000-7f0570021000 rw-p 00000000 00:00 0 
7f0570021000-7f0574000000 ---p 00000000 00:00 0 
7f0574000000-7f0574021000 rw-p 00000000 00:00 0 
7f0574021000-7f0578000000 ---p 00000000 00:00 0 
7f0578000000-7f0578021000 rw-p 00000000 00:00 0 
7f0578021000-7f057c000000 ---p 00000000 00:00 0 
7f057c000000-7f057c021000 rw-p 00000000 00:00 0 
7f057c021000-7f0580000000 ---p 00000000 00:00 0 
7f058008b000-7f05802db000 rw-p 00000000 00:00 0 
7f05802db000-7f05802dc000 ---p 00000000 00:00 0 
7f05802dc000-7f0580adc000 rw-p 00000000 00:00 0 
7f0580adc000-7f0580add000 ---p 00000000 00:00 0 
7f0580add000-7f058132d000 rw-p 00000000 00:00 0 
7f058132d000-7f058132e000 ---p 00000000 00:00 0 
7f058132e000-7f0581bee000 rw-p 00000000 00:00 0 
7f0581bee000-7f0581bef000 ---p 00000000 00:00 0 
7f0581bef000-7f05823ef000 rw-p 00000000 00:00 0 
7f05823ef000-7f05823f0000 ---p 00000000 00:00 0 
7f05823f0000-7f0582c30000 rw-p 00000000 00:00 0 
7f0582c30000-7f0582c31000 ---p 00000000 00:00 0 
7f0582c31000-7f0583431000 rw-p 00000000 00:00 0 
7f0583431000-7f0583432000 ---p 00000000 00:00 0 
7f0583432000-7f0583c32000 rw-p 00000000 00:00 0 
7f0583c32000-7f0583c33000 ---p 00000000 00:00 0 
7f0583c33000-7f0584453000 rw-p 00000000 00:00 0 
7f0584453000-7f0584553000 rw-p 00000000 00:00 0 
7f0584553000-7f0584564000 rw-p 00000000 00:00 0 
7f0584564000-7f0586564000 rw-p 00000000 00:00 0 
7f0586564000-7f05966e4000 ---p 00000000 00:00 0 
7f05966e4000-7f05966e5000 rw-p 00000000 00:00 0 
7f05966e5000-7f05b66e4000 ---p 00000000 00:00 0 
7f05b66e4000-7f05b66e5000 rw-p 00000000 00:00 0 
7f05b66e5000-7f05c8594000 ---p 00000000 00:00 0 
7f05c8594000-7f05c8595000 rw-p 00000000 00:00 0 
7f05c8595000-7f05ca96a000 ---p 00000000 00:00 0 
7f05ca96a000-7f05ca96b000 rw-p 00000000 00:00 0 
7f05ca96b000-7f05cade4000 ---p 00000000 00:00 0 
7f05cade4000-7f05cade5000 rw-p 00000000 00:00 0 
7f05cade5000-7f05cae64000 ---p 00000000 00:00 0 
7f05cae64000-7f05caec8000 rw-p 00000000 00:00 0 
7f05caec8000-7f05caecb000 r--p 00000000 08:20 33558859                   /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7f05caecb000-7f05caedd000 r-xp 00003000 08:20 33558859                   /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7f05caedd000-7f05caee1000 r--p 00015000 08:20 33558859                   /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7f05caee1000-7f05caee2000 r--p 00018000 08:20 33558859                   /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7f05caee2000-7f05caee3000 rw-p 00019000 08:20 33558859                   /usr/lib/x86_64-linux-gnu/libgcc_s.so.1
7f05caee3000-7f05caf05000 r--p 00000000 08:20 33558834                   /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f05caf05000-7f05cb07d000 r-xp 00022000 08:20 33558834                   /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f05cb07d000-7f05cb0cb000 r--p 0019a000 08:20 33558834                   /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f05cb0cb000-7f05cb0cf000 r--p 001e7000 08:20 33558834                   /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f05cb0cf000-7f05cb0d1000 rw-p 001eb000 08:20 33558834                   /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f05cb0d1000-7f05cb0d7000 rw-p 00000000 00:00 0 
7f05cb0d7000-7f05cb0e4000 r--p 00000000 08:20 33558876                   /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f05cb0e4000-7f05cb18b000 r-xp 0000d000 08:20 33558876                   /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f05cb18b000-7f05cb224000 r--p 000b4000 08:20 33558876                   /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f05cb224000-7f05cb225000 r--p 0014c000 08:20 33558876                   /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f05cb225000-7f05cb226000 rw-p 0014d000 08:20 33558876                   /usr/lib/x86_64-linux-gnu/libm-2.31.so
7f05cb226000-7f05cb2bc000 r--p 00000000 08:20 33558944                   /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28
7f05cb2bc000-7f05cb3ad000 r-xp 00096000 08:20 33558944                   /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28
7f05cb3ad000-7f05cb3f6000 r--p 00187000 08:20 33558944                   /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28
7f05cb3f6000-7f05cb3f7000 ---p 001d0000 08:20 33558944                   /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28
7f05cb3f7000-7f05cb402000 r--p 001d0000 08:20 33558944                   /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28
7f05cb402000-7f05cb405000 rw-p 001db000 08:20 33558944                   /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.28
7f05cb405000-7f05cb408000 rw-p 00000000 00:00 0 
7f05cb408000-7f05cb409000 r--p 00000000 08:20 33558845                   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f05cb409000-7f05cb40b000 r-xp 00001000 08:20 33558845                   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f05cb40b000-7f05cb40c000 r--p 00003000 08:20 33558845                   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f05cb40c000-7f05cb40d000 r--p 00003000 08:20 33558845                   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f05cb40d000-7f05cb40e000 rw-p 00004000 08:20 33558845                   /usr/lib/x86_64-linux-gnu/libdl-2.31.so
7f05cb40e000-7f05cb410000 r--p 00000000 08:20 33558932                   /usr/lib/x86_64-linux-gnu/librt-2.31.so
7f05cb410000-7f05cb414000 r-xp 00002000 08:20 33558932                   /usr/lib/x86_64-linux-gnu/librt-2.31.so
7f05cb414000-7f05cb416000 r--p 00006000 08:20 33558932                   /usr/lib/x86_64-linux-gnu/librt-2.31.so
7f05cb416000-7f05cb417000 r--p 00007000 08:20 33558932                   /usr/lib/x86_64-linux-gnu/librt-2.31.so
7f05cb417000-7f05cb418000 rw-p 00008000 08:20 33558932                   /usr/lib/x86_64-linux-gnu/librt-2.31.so
7f05cb418000-7f05cb41e000 r--p 00000000 08:20 33558928                   /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f05cb41e000-7f05cb42f000 r-xp 00006000 08:20 33558928                   /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f05cb42f000-7f05cb435000 r--p 00017000 08:20 33558928                   /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f05cb435000-7f05cb436000 r--p 0001c000 08:20 33558928                   /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f05cb436000-7f05cb437000 rw-p 0001d000 08:20 33558928                   /usr/lib/x86_64-linux-gnu/libpthread-2.31.so
7f05cb437000-7f05cb43b000 rw-p 00000000 00:00 0 
7f05cb43b000-7f05cb43f000 r--p 00000000 08:20 33558930                   /usr/lib/x86_64-linux-gnu/libresolv-2.31.so
7f05cb43f000-7f05cb44f000 r-xp 00004000 08:20 33558930                   /usr/lib/x86_64-linux-gnu/libresolv-2.31.so
7f05cb44f000-7f05cb453000 r--p 00014000 08:20 33558930                   /usr/lib/x86_64-linux-gnu/libresolv-2.31.so
7f05cb453000-7f05cb454000 r--p 00017000 08:20 33558930                   /usr/lib/x86_64-linux-gnu/libresolv-2.31.so
7f05cb454000-7f05cb455000 rw-p 00018000 08:20 33558930                   /usr/lib/x86_64-linux-gnu/libresolv-2.31.so
7f05cb455000-7f05cb459000 rw-p 00000000 00:00 0 
7f05cb45c000-7f05cb45d000 r--p 00000000 08:20 33558812                   /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f05cb45d000-7f05cb480000 r-xp 00001000 08:20 33558812                   /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f05cb480000-7f05cb488000 r--p 00024000 08:20 33558812                   /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f05cb489000-7f05cb48a000 r--p 0002c000 08:20 33558812                   /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f05cb48a000-7f05cb48b000 rw-p 0002d000 08:20 33558812                   /usr/lib/x86_64-linux-gnu/ld-2.31.so
7f05cb48b000-7f05cb48c000 rw-p 00000000 00:00 0 
7fffb1c9d000-7fffb1cbe000 rw-p 00000000 00:00 0                          [stack]
7fffb1d68000-7fffb1d6c000 r--p 00000000 00:00 0                          [vvar]
7fffb1d6c000-7fffb1d6e000 r-xp 00000000 00:00 0                          [vdso]
```

Đọc source của ollama version 0.1.29 ta thấy rằng các shared object này được load vào khi một llm server mới được start

`routes.load` => `llm.New` => `newLlmServer` => `newDynExtServer` => `dyn_init` => `LOAD_LIBRARY` => `dlopen`

![image](https://github.com/user-attachments/assets/4eeee9d8-6dfc-4934-b3a2-ac8b111fd6b1)

`routes.load` có thể được trigger thông qua một số route, trong đó có `/api/chat`

Tuy nhiên khi nhìn vào tên của folder chứa các shared object thì có vẻ nó được random, bước kế tiếp ta cần tìm cách leak được tên của folter này

### Leaking tmp dir

Việc đầu tiên mình nghĩ tới là đọc một file log nào đó của ollama, vì như ta thấy thông tin chứa tên folder này được hiển thị bên trong log

![image](https://github.com/user-attachments/assets/4e4ac6ca-5dc4-4121-bf9c-250e8a95da6f)

Sau khi mò mẫm mình cũng không tìm thấy file nào, cách thứ 2 mình nghĩ đến là leak tên thông qua việc đọc `/proc/<id>/maps` do nếu nó được load vào thì libc sẽ mmap một region cho riêng nó

![image](https://github.com/user-attachments/assets/c48a4012-4502-4f3b-a621-e4b8815eacba)

Vấn đề là nếu ta dùng lại read primitive của CVE thì server bất ngờ bị crash, mình nhận ra là cái crash xuất phát từ một dòng ghi log

![image](https://github.com/user-attachments/assets/7043f839-2a37-45b0-ac5f-3110453ec11b)

Vì trước construct data để upload lên rogue server của ta, ollama gọi os.Stat nhằm check length của file, tuy nhiên như ta biết thì các file trong `/proc` rất đặc biệt và nó không hẳn là 1 file thông thường, các file này được kernel generate on the flight và nếu gọi os.Stat thì length sẽ là 0

![image](https://github.com/user-attachments/assets/d9cd1f85-aa10-4eea-89c0-07cf2673b2fb)

Do size là 0 nên vòng for sẽ không chạy, do đó ở dòng log bên dưới sẽ bị out of bound access

### Work around

Sau khi ngồi audit thêm thì mình để ý thấy ở route `/api/show` có một bug path traversal khác:

`ShowModelHandler` => `GetModelInfo` => `GetModel`

![image](https://github.com/user-attachments/assets/277a572d-6c05-482b-9e2a-72afd568f2a7)

Nên mình nghĩ nếu dùng write primitive để ghi đè file manifest và control được `filename` (cụ thể là ở `Digest`) thì ta có thể đọc được `/proc/self/maps`

```
{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:34bb5ab01051a11372a91f95f3fbbc51173eed8e7f13ec395b9ae9b8bd0e242b","size":561},"layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff","size":2019377376},{"mediaType":"application/vnd.ollama.image.template","digest":"../../../../../../../../../../../proc/self/maps","size":1429},{"mediaType":"application/vnd.ollama.image.license","digest":"sha256:fcc5a6bec9daf9b561a68827b67ab6088e1dba9d1fa2a50d7bbcc8384e0a265d","size":7711},{"mediaType":"application/vnd.ollama.image.license","digest":"sha256:a70ff7e570d97baaf4e62ac6e6ad9975e04caa6d900d3742d37698494479e0cd","size":6016},{"mediaType":"application/vnd.ollama.image.params","digest":"sha256:56bb8bd477a519ffa694fc449c2413c6f0e1d3b1c88fa7e3c9d88d3ae49d4dcb","size":96}]}
```

![image](https://github.com/user-attachments/assets/d5c864d7-721c-4d62-a252-d4811ef8c167)

### Zipslip

Bên cạnh việc có write primitive thông qua việc pull model từ registry thì ở `/api/create` mình có tìm thấy một bug zipslip khác cho phep ghi file đến vị trí tùy ý ở hàm `convertSafetensors` trong route `/ap/create`

![image](https://github.com/user-attachments/assets/50a7ad7f-bb91-4db7-83dc-cb54d38453b8)

Nên mình có chơi trội một tí bằng cách lấy write primitive để ghi file zip sau đó trigger zipslip để lấy write primitive =))) vl thua

### Shared Object overwriting

Tưởng chừng đến đây mọi việc đã xong, do chỉ cần ghi đè file shared object là RCE, nhưng...

![image](https://github.com/user-attachments/assets/3a322d48-7c72-4cbd-bf85-36ceb3496b92)

Somehow sau khi ghi đè và trigger load so thì server crash luôn, sau khi ngồi debug mình nhận ra cái này liên quan đến cách một shared object được load vào memory. Đầu tiền dlopen sẽ mmap các region cho file shared object, sau đó linker thực hiện relocate để biến các offset trong file so thành các địa chỉ bằng cách lấy base+offset. Khi mình ghi đè nội dung vật lý của file, nó vô tình ghi đè luôn nội dung trong memory của file, dẫn đến việc các pointer lúc này lại trở thành offset, khi gọi dlsym để load các symbol ra thì sẽ segmentation fault. Bạn sẽ hỏi rằng tại sao không ghi đè `_init` hay các constructor để nó chạy ngay khi được `dlopen`? Đó chắc chắn là cách đầu tiên mình nghĩ đến, nhưng cách implement của ollama lại rất sai, thay vì thực hiện `dlclose` để giải phóng region của so sau khi dùng xong thì nó cứ để đó, ở lần start llm server sau thì shared object lại tiếp tục được dlopen lại, libc khi `dlopen` sẽ track xem so đã được load vào trong memory chưa thông qua reference counting, nếu phát hiện SONAME đã tồn tại thì nó sẽ không làm gì cả, các ptr cũng không được relocate, constructors và `_init` cũng sẽ không chạy.

Đến đây mình có thể ý thực chất có 1 điều kiện khiến ollama gọi `dlclose`

![image](https://github.com/user-attachments/assets/e646db7f-a1cb-4227-9dee-9f82baea4dfc)

Tuy nhiên thì mình nhận ra quả điều kiện này cũng troll nốt, đúng ra phải deref cái ptr đó ra để check chứ không phải check bản thân cái ptr

### Prelinking 

Cuối cùng thì mình nghĩ do đã leak được mem nên có thể làm sao đó recover được các ptr của file so thôi, mình chắc chắn k muốn làm điều đó một cách thủ công, nên mình tìm ra 1 cách là dùng prelink để relocate so về một base address, sơ qua về prelink thì nó là 1 tính năng cũ dùng để speedup các phần mềm khi nó load các so vào và không cần thực hiện relocate mỗi lần load. Tuy nhiên sau khi relocate mình nhận thấy function ptr mà dlsym trả về sai bét.

![image](https://github.com/user-attachments/assets/4b6139e3-e1fe-48ef-b50b-096e84e9ab87)

Mình mày mò tìm lý do, cuối cùng khi lấy địa chỉ mà dlsym trả về trừ đi cho function ptr thực tế thì ra đúng bằng giá trị base address

![image](https://github.com/user-attachments/assets/448b2224-ab3e-4554-bea6-579daca23be9)

Mình nhận ra cái prelink đã relocate sai và nó relocate luôn cả các offset trong symtab, cách fix là mình patch luôn cái file so đã prelink lại và ghi chỗ symtab entry đó lại thành offset, cuối cùng là mình ghi shellcode để reverse shell vào `llama_server_init` và chờ nó gọi để trigger rev shell thôi

![image](https://github.com/user-attachments/assets/b90be8a9-67f8-4299-b329-69b992800753)

[poc.zip](https://github.com/user-attachments/files/17306311/poc.zip)

### Flag

Sau khi nói cho anh Jang thì anh Jang có hỗ trợ mình mở lại server ollala để test exploit, cảm giác giống pwn2own vl nếu có thêm điều kiện sau 3 shot là tạch, cơ mà may mắn là exploit của mình với điều kiện mạng tốt thì chạy khá stable

![image](https://github.com/user-attachments/assets/63c92884-c3df-4ffb-aa10-9a66370ef28d)

![image](https://github.com/user-attachments/assets/b23f508c-337e-464c-a587-faa64f603219)

`CIS2024{VuBpIGu7IG5naCkgbexuaCB0aOljIHRo3WkgY2jJIHbsIGNvbiBxdfcgbvMgdHLNbmcgZOVuZw==}`

### Conclusion

Ollala là một bài khá vip và nó giúp mình làm quen với việc audit golang hơn, cũng như mình học thêm được nhiều thứ hơn về linking, shared object files, ... Cảm ơn anh Jang đã tạo điều kiện để bọn em mày mò nghiên cứu. Cơ mà em nghĩ với format 8 tiếng thì làm ra bài này hơi khó...

### Bonus

PoC in action (đừng kì thị bandicam mà):

https://github.com/user-attachments/assets/a0afcd71-9dd5-4974-8f3a-65266f911b9b


