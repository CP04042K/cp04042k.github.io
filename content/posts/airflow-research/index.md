---
title: "Apache Airflow not so Remote Code Execution"
description: "Airflow researching"
summary: "Airflow researching"
categories: ["Research"]
tags: ["Web"]
#externalUrl: ""
date: 2024-05-20
draft: false
authors:
  - Shin24
---

Apache Airflow là một platform quản lý workflow, nghĩa là ta có thể setup các task chạy theo một trình tự nhất định để xử lý một loại dữ liệu hoặc cho nó làm một nhiệm vụ gì đó. Apache Airflow nằm trong scope của Internet Bug Bounty trên HackerOne chi trả bounty cho các researcher và cả maintainer để make internet safer, tuần vừa rồi mình có ngồi research lại airflow để tìm xem có gì hay ho không, mình có tìm được một vài bug nhưng đến cuối cùng thì lại bị reject bởi Apache, do đó mình lên bài này để note lại những gì mà mình tìm được.

## Checking out source and debug setup
Trước tiên ta cần pull source của Airflow về, theo như installation instruction của Airflow thì ta có thể cài đặt thông qua pip, tuy nhiên đến tận vài ngày sau thì mình thấy source trên github và source khi cài từ pip có vài phần khác nhau (bản từ pip là stable release, là một security researcher đúng ra mình phải cài đặt trực tiếp từ github). Để cài đặt từ github thì ta chỉ cần clone repo về, cd vào thư mục và run `pip install .`. Về việc debug thì cũng khá dễ, sau khi cài đặt ta sẽ có một file airflow executable

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c276a994-ae6e-4dee-83bc-5b1d02357897)

Bản chất cũng là python thôi

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/08519af2-d07f-40e9-b976-e7af5ba17e1d)

Từ đây ta có thể setup vscode python launch debug để debug file airflow, chỉnh `"justmycode": false` để step vào lib và debug như bình thường

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8b28f2e2-a73c-4bed-8863-c7bf99d3b566)

Ở đây mình có copy sang một file run.py để cho tiện

## Tiếp cận
Việc đầu tiên khi research airflow đó là mình xem lại các bug cũ, thật ra trước đây mình cũng từng làm airflow rồi nên cũng đã nắm được cách hoạt động cũng như Design pattern của nó. Nếu các bạn lên hacktivity của airflow sẽ thấy đa phần các bug gần đây sẽ liên quan đến vấn đề authorization, có một bug về logic liên quan đến Xcom deserialization (pickle deserialization) nhưng là low do điều kiện trigger của nó khó xảy ra. Do sau khi xem xét thì mình cảm thấy một attack surface khá lớn đó là các provider của airflow

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/dd7ef029-61ab-4dcb-a999-f64369b201ef)

Một tính năng khá thú vị của airflow là cho phép tạo các connections để reuse lại ở các dags (các dags là cha của các tasks), và các connections thì sẽ có nhiều type tương ứng với nhiều loại provider, các provider này sẽ handle việc connect đến host theo từng type tương ứng. Mình có nhớ lại một bug của anh Sơn Trần về Mysql provider khi mà ta có thể đọc được một file bất kỳ từ server thông qua LOAD LOCAL FILE: https://dev.mysql.com/doc/refman/8.0/en/load-data.html

## Provider exploit

Mình quyết định đi dạo một vòng qua các provider, tìm thấy report của một bug cũ trong ODBC provider: https://github.com/advisories/GHSA-9766-v29c-4vm7

Mình xem lại đoạn code của ODBC provider

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9baa774a-6c97-48f2-bce8-20a3c13e6fbc)

Okey... vậy là nó ngăn việc set `driver` nếu không được config, nhưng nhìn vào đoạn construct connection string bên dưới:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/57e45e2f-28c8-4ea3-8d08-6056c5643cc6)

Vậy thì ta có thể inject `driver` thông qua các tham số khác như host vào connection string? Để kiểm chứng thì mình tạo một shared object file với constructor gọi đến `system`, dùng tính năng connection testing của apache để thực hiện connect đến server của mình

```C
#include <stdlib.h>

__attribute__ ((constructor)) int test() {
    system("echo hacked > /tmp/a.txt; /mnt/c/Windows/system32/calc.exe");
}

int main() {
    return 0;
}
```

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/83cb94a7-2f1f-42bd-be4b-9c5c87f0913b)

Oke ngon, nhưng hạn chế là ta cần phải tìm cách write một file lên server để load vào, trong lúc tìm kiếm thì mình tìm ra một bug khác nằm trong Trino provider 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/63cc56be-7d62-4ae0-9801-0a3286515801)

Sau đó jwt cùng được gửi với request Kerberos

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c33c4cc9-fcb2-4627-a939-c6bb503a5e1b)

Vậy là ta có thể đọc được nội dung file nếu ta hứng request bằng server của mình? 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/a9680590-4587-495e-8a7c-be2868ddf5ab)

Không cần đến điều đó, vì khi cố gắng gửi kèm JWT với request thì newline bên trong file sẽ làm cho request header value bị invalid, trả về exception, cộng với việc không xử lý exception khiến cho nội dung file trả thẳng về response. Với 2 bug này thì minh thử gửi report cho Apache security team và nhận được hồi đáp sau:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/db409536-a96d-4163-ba19-d3d9b265f15e)

Ok so...họ đã fix vấn đề ở các provider bằng cách disable tính năng connection testing by default thay vì fix bug ở từng provider... Fail rồi thì thôi, mình đi tìm bug khác

## Airflow internal API
Mình có phát hiện là Airflow có một tính năng có thể bật một internal API, đây là một server riêng biệt được dùng để tách biệt API và Airflow webserver. Đây là một RPC server và rely on deserialization để xử lý call request, tuy nhiên cơ chế deserialization xử dụng không phải là pickle mà là self-implement, ít chức năng hơn và cũng đơn giản hơn
### Insecure deserialization
Để thực hiện RPC call thì airflow nhận method name và check trong một list có sẵn để xem method đó có được registered hay không, sau đó deserialize các tham số và truyền vào method call. Khi deserialization một tham số với type là PARAM thì Airflow sẽ call `_deserialize_param`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/36ae933e-6823-4f21-a7d5-40d468897bb5)

Tại đây sẽ sẽ gọi `import_string` với thuộc tính `__class` mà ta truyền vào, bên trong `import_string` sẽ gọi `import_module` và `getattr` để import và lấy class cần thiết

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/3d99adb3-9484-4d3f-b360-c8650ccb9358)

Cuối cùng là instantiate class đó với các arguments mà ta truyền vào, tuy nhiên ta chỉ có thể truyền vào các arguments trong có whitelist 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/dfec6ea0-2fc3-4169-a1cd-424a123b00b8)

Một điều mà mình thấy khá bựa ở python là việc gọi một function và instatiate một class lại y hệt nhau, dẫn đến việc nếu dùng cú pháp như trên thì không nhất thiết phải là một class, nó có thể là một function. Với việc ta không hoàn toàn control được các arguments thì ta không thể gọi đến `subprocess.Popen` hay `os.system` được, nhưng vẫn có thể call các function không cần arguments, ví dụ ở đây mình call đến `builtins.input` để làm treo server (dos)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/d628944e-4ac3-491b-86a9-8227e5e6b2c2)

Mặc định Airflow dùng 4 worker gunicorn để handle connections 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9306d769-36b5-44be-ac2b-84bbb775fbd3)

Nếu mình gửi 4 request như trên thì server sẽ treo hoàn toàn, đây là impact mà mình lead ra được

### Insecure deserialization 2
Sau khi phát hiện source ở git và source khi cài bằng pip khác nhau, mình cài lại source từ git và tại các nhánh deserialization mình tìm thấy một sink dễ hơn

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c2d0a9b1-cadf-4751-846c-19a7e65358d9)

Như thế này thì không còn gì để nói nữa

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/793e08b8-70fb-497c-9a9b-acab5185b737)

Sau phát hiện này thì mình lại lần nữa report cho Airflow, nhưng câu trả lời nhận được vẫn là không

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/08aefd56-ab58-4ab5-beb2-26ac77fa7b00)

## Conclusion
Quan điểm của mình về bug trong RPC server thì ta cần set một biến môi trường để bật tính năng experimental này lên nên khá khó cho việc một user nào đó vô tình bật nó lên được, tuy nhiên một bug của một experimental feature thì vẫn nên được xem xét vì nếu trong giai đoạn phát triển không fix nó đi thì khi ra production nó sẽ thật sự thành bug. Thôi thì lần này cũng khá khoai, có lẽ mình sẽ move on với một target khác. 
