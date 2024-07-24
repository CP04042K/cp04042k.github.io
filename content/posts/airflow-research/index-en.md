---
title: "[EN] Apache Airflow not so Remote Code Execution"
description: "Airflow researching"
summary: "Airflow researching"
categories: ["Research"]
tags: ["Web"]
#externalUrl: ""
date: 2024-06-17
draft: false
authors:
  - Shin24
---


Apache Airflow is a workflow management platform, meaning we can set up tasks to run in a certain order to process a type of data or let it do a certain task. Apache Airflow is within the scope of the Internet Bug Bounty on HackerOne, which pays bounties to researchers and maintainers to make the internet safer. Last week, I researched Airflow again to see if there was anything interesting. I found a few bugs, but in the end it was all rejected by Apache, so I made this post to note what I found.

## Checking out source and debug setup
First we need to pull the source code of Airflow. According to Airflow's installation instructions, we can install via pip, but a few days later I saw that the source on github and the source when installed from pip have a few different parts. (The version from pip is a stable release, as a security researcher I should have installed it directly from github). To install from github, we just need to clone the repo, `cd` into the directory and run `pip install .`. Regarding debugging, it is quite easy, after installation we will have an executable airflow file

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c276a994-ae6e-4dee-83bc-5b1d02357897)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/08519af2-d07f-40e9-b976-e7af5ba17e1d)

From here we can setup vscode python launch debug to debug airflow files, set `"justmycode": false` to step into the Airflow library and start debugging.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/8b28f2e2-a73c-4bed-8863-c7bf99d3b566)

Here I have copied it to a `run.py` file for convenience

## Approaching
The first thing when researching airflow is to review old CVEs. Actually, I have reviewed Airflow before so I already understand how it works and its design pattern. If you go to airflow's hacktivity, you will see that most of the recent bugs are related to authorization issues, there is a logic bug related to Xcom deserialization (pickle deserialization) but the severity is low because its trigger conditions are unlikely to occur. After looking at some of it, I feel that a rather large attack surface is the airflow providers.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/dd7ef029-61ab-4dcb-a999-f64369b201ef)

An interesting feature of Airflow is that it allows creating connections to reuse in DAGs (DAGs are like the parents of tasks), and connections will have many types corresponding to many types of providers, these providers will handle connections to the host according to each corresponding type. I remembered a bug from Son Tran about the Mysql provider where we can read any file from the server through LOAD LOCAL FILE: 
https://dev.mysql.com/doc/refman/8.0/en/load-data.html

## Provider exploit

I decided to play around with the providers and found a report of an old bug in the ODBC provider: https://github.com/advisories/GHSA-9766-v29c-4vm7

Let's review the code of the ODBC provider:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9baa774a-6c97-48f2-bce8-20a3c13e6fbc)

Okay... so it prevents setting `driver` if not specifically configured, but take a look at the construction of the connection string below:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/57e45e2f-28c8-4ea3-8d08-6056c5643cc6)

So we can inject `driver` through other parameters like host into the connection string? For testing, I created a shared object file with GCC `constructor` to call `system`, using Apache's connection testing feature to connect to an arbitrary server.

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

Ok nice, but the limitation is that we need to find a way to write a file to the server to load. While searching for a arbitrary file write, I found another bug in the Trino provider.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/63cc56be-7d62-4ae0-9801-0a3286515801)

The jwt is then sent along with the Kerberos request

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c33c4cc9-fcb2-4627-a939-c6bb503a5e1b)

So we can read the file content if we make Ariflow to send a Kerberos authentication request to our server?

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/a9680590-4587-495e-8a7c-be2868ddf5ab)

There is no need for that, when trying to attach the JWT with the request, the newline inside the file will cause the request header value to be invalid. Plus when returning an exception, it's not handled correctly and will cause the file content to be returned directly to the response. With these 2 bugs, I sent a report to the Apache security team and received the following response:

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/db409536-a96d-4163-ba19-d3d9b265f15e)

Ok so... they already fixed the problem in the providers by disabling the connection testing by default instead of fixing the bug in each provider... It's failed then, I'll go for another attack surface

## Airflow internal API
I discovered that Airflow has a feature that can enable an internal API, this is a separate server used to separate the API and the Airflow webserver. This is an RPC server and relies on deserialization to handle call requests, however the deserialization mechanism used is not pickle but a self-implement, with less functionality and simpler deserialization mechanism.

### Insecure deserialization
To make an RPC call, airflow receives the method name and checks in an pre-defined list to see if the method is registered or not, then deserializes the parameters and passes them to the method call. When deserializing a parameter with type PARAM, Airflow will call `_deserialize_param`

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/36ae933e-6823-4f21-a7d5-40d468897bb5)

Here we will call `import_string` with the `__class` attribute we pass in. Inside `import_string` it will call `import_module` and `getattr` to import and get the necessary class.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/3d99adb3-9484-4d3f-b360-c8650ccb9358)

Finally, instantiate that class with the arguments we pass in, however we can only pass in arguments in the whitelist.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/dfec6ea0-2fc3-4169-a1cd-424a123b00b8)

One thing that I find quite "insecure" in python is that calling a function and instantiating a class use quite the same syntax, leading to the fact that if you use the above syntax, it doesn't necessarily have to be a class, it can be a function. Since we cannot completely control the arguments, we cannot call `subprocess.Popen` or `os.system`, but we can still call functions without arguments, for example, here we call `builtins.input` to hang the server (dos)

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/d628944e-4ac3-491b-86a9-8227e5e6b2c2)

By default Airflow uses 4 gunicorn workers to handle connections 

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/9306d769-36b5-44be-ac2b-84bbb775fbd3)

If I send 4 requests as above, the server will completely hang. 

### Insecure deserialization 2
After discovering that the source code in git and the source code when installed with pip are different, I reinstalled the source from git and in the deserialization branches I found an easier sink.

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/c2d0a9b1-cadf-4751-846c-19a7e65358d9)

No need to say more

![image](https://github.com/CP04042K/cp04042k.github.io/assets/35491855/793e08b8-70fb-497c-9a9b-acab5185b737)

