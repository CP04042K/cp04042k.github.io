---
title: "SekaiCTF 2024: "
description: "Quick note about some nice challenges"
summary: "Quick note about some nice challenges"
categories: ["Writeup"]
tags: ["Web"]
#externalUrl: ""
date: 2024-04-27
draft: false
authors:
  - Shin24
---

## Context

 Bài cho phép ta upload một file HTML lên, trước khi upload nội dung file sẽ được check:
- Phần tử đầu tiên của tag head phải có innerHTML là `<meta http-equiv="Content-Security-Policy" content="default-src 'none'">`, nghĩa là ta bắt buộc phải đính kèm CSP vào file HTML
- Dùng chrome truy cập vào nội dung của HTML thông qua scheme `data:` và check xem có các tag/attributes không hợp lệ hay không

Hint mà bài cho như sau:

![image](https://github.com/user-attachments/assets/1caafe86-824e-40bc-9cce-374259fc2ff2)

Mình sẽ focus vào solution của **@BitK**, modified version (hackvertor):

```html
<html>
<head>
<!-- <@repeat(9000)>A<@/repeat>
<@repeat(9000)>A<@/repeat>
<@repeat(9000)>A<@/repeat>
<@repeat(9000)>A<@/repeat>
<@repeat(9000)>A<@/repeat>
<@repeat(9000)>A<@/repeat> -->
<!-- %1b$B AAAAAA --> <-- %1b(B -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">

</head>
<body>
<input onfocusin='alert(1);'>
```

## Streamed vs Non-streamed HTML parsing

Đầu tiên thì stream là gì? Stream là một dãy byte được truyền từ đầu đến đích, ví dụ như HTTP stream chẳng hạn. Lý do mà nó là một stream là vì ta không biết chắc chắn rằng data khi nào sẽ arrive đầy đủ, trong context của chrome khi ta truy cập vào url `http://example.com` thì chrome sẽ thực hiện request data từ server, nhận về một HTTP stream và parse HTTP response stream này. Trong trường hợp response ngắn thì nó sẽ nằm gọn trong một TCP packet, chrome nhận gói TCP này và thực hiện parse HTML bên trong đó, nếu response đạt độ dài nhất định thì response sẽ bị split thành các TCP chunks và arrive ở các thời điểm khác nhau, mỗi khi nhận một chunks chrome sẽ thực hiện parse phần HTML nằm trong chunk đó. Đối với `data:` scheme, đây là một non-stream URI bởi vì chrome đã hoàn toàn biết được nội dung cần phải render. Vậy thì streamed và non-streamed parsing trong chrome khác nhau như thế nào?

Có một vấn đề khác của bài đó là ở endpoint nhận về HTML file không có charset trong phần response header, gần đây sonar source đã có một bài research về vấn đề này tại: https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters

Sự khác biệt của streamed và non-streamed parsing đó là streamed data nếu quá dài sẽ được parse theo từng chunks, non-stream sẽ được parse thành 1 chunk duy nhất, và trong quá trình parse đó thì charset detect là một phần

## Missing charset in non-streamed parsing

Cú pháp của `data:` scheme: 

![image](https://github.com/user-attachments/assets/3c84c99e-1f05-48dc-aab8-e39361268300)

Lấy ví dụ ta có `data:text/html;base64...` thì ở đây vì thiếu charset nên chrome sẽ tự detect charset encoding nên sử dụng

![image](https://github.com/user-attachments/assets/756799a2-6b19-4beb-a757-b0f63586b7a6)

Như ở trên khi áp dụng kỹ thuật mà sonar source trình bày, sau đó thử kiểm tra `document.charset` thì thấy chrome đã tự detect rằng charset cần sử dụng là `ISO-2022-JP`, với payload của BitK thì `\x1B$B` sẽ switch charset của các ký tự tiếp theo sang `JIS X 0208-1983`, khiến cho các ký tự tiếp theo bị encode theo cách khác (cho đến khi gặp `\x1B(B` và switch lại thành ASCII) và làm mất đi phần `AAAAAA --> <--`, khiến cho nó thành 

```html
<!-- ... -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">
```

Vậy là vào lúc check, phần HTML trên sẽ pass qua phần check CSP

## Missing charset in streamed parsing

Đối với streamed parsing thì mọi thứ hơi khác một tí, việc padding `AAAA...` là để response sẽ bị split thành nhiều chunks, khi chrome thực hiện parse chunks đầu tiên nó sẽ thực hiện detect charset, do phần chứa các ký tự của charset `ISO-2022-JP` đã bị đẩy qua chunk khác nên vào lúc này document chỉ chứa các ký tự ASCII, charset được detect sẽ là `windows-1252`, khi thực hiện parse đến chunk thứ 2 (hoặc thứ n) thì lúc này charset đã được quyết định, do đó phần comment sau khi parse sẽ là:

```html
<!-- %1b$B AAAAAA --> <-- %1b(B -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">
```

Nghĩa là lúc này ta sẽ có một comment node, **một string node** và tag meta. Ta sẽ đi qua spec của W3C một tí

![image](https://github.com/user-attachments/assets/926334d8-68ea-4742-9c8a-bb9719fb7f24)

Để ý phần bên dưới:

![image](https://github.com/user-attachments/assets/3b0ed2f5-4d9e-496f-94b4-13c109815f56)

Nghĩa là nếu có một node không nằm trong các node hợp lệ trong `head` thì lúc này việc parse thẻ `head` sẽ xem như kết thúc và các node phía sau sẽ được insert vào phía sau thẻ `head`, string node bên trên là một node không hợp lệ do đó thẻ meta sẽ bị nằm ngoài head. Nếu một thẻ meta được dùng để set CSP nhưng lại nằm ngoài thẻ `head` thì nó sẽ bị **ignored**, do đó lúc này document sẽ không có CSP (WIN!!). 

![image](https://github.com/user-attachments/assets/8de24d87-8d98-42c9-815f-77efc679ca7b)

![image](https://github.com/user-attachments/assets/9dc59de8-1cb5-496f-9541-64d05f5a007b)

Phần bypass attributes còn lại là sử dụng tag `input` và một event handler chưa bị blacklist đó là `onfocusin`, thế là xong.

