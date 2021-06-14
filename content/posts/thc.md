+++
date = "2021-06-14"
author = "biplavxyz"
title = "Elf x64 - Right on Time - THCon CTF - Radare2 Write Mode"
+++
Greetings everyone!  
This writeup is going to be about one of the reversing challenges from THCon CTF 2021.  
Let's start!!!!  
Here, Name of the binary is chall.bin.

First, Trying to run the binary without any input prints that we need to provide an argument and exits the program.So, let's try by passing an argument and here it prints `Nope sorry, try again` and exits the program.


![1](/thc1.png) 
So, I loaded the binary in write mode using radare2 with command:
```bash
r2 -w chall.bin
```
I got the binary details, and strings using `iz` and `iI` commands respectively. It seems that binary is not stripped, but has stack protection turned on as canary is set to true.  
Also, after checking strings, it seems like the binary prints `[+] Well done ! Here is the flag :` once we provide it correct flag.
![2](/thc2.png)
Then, I analysed the binary using `aaa` command, and listed all functions with `afl` command. I saw main function in there, so I used `s main` command to seek to the main function.
![3](/thc3.png)
As radare2 has an awesome `Graph Mode` which can use with `VV` command, I switched to graph mode to get an overview of how the given binary works.  
There were so many assembly instructions which weren't of much importance to us. But, I was able to know how the program works by looking at graph. Such graphs are very helpful while analyzing complex binaries.  
![4](/thc4.png)
In this challenge, first comparision checks if a parameter is provided, and if a parameter is provided jumps to `0x1c0b` and continues execution, otherwise the program jumps to `0x1c81` and exits. Then, in another box within the graph, we can see another comparision of `qword [var_1c8h]` with `rax` register, and if they are equal, the programs gives us the flag, otherwise it exits.
![5](/thc5.png)
Here, its important to focus on the instruction 
```jne 0x1c6e```

It simply jumps to `0x1c6e` if the value in `rax` register doesn't match with the value of `qword [var_1c8h]`. And `0x1c6e` is the location which prints `Nope Sorry, Try Again` and exits.

![6](/thc6.png)

So, how about we change the instruction 
`jne 0x1c6e` to `je 0x1c6e`  which will cause the program to jump to `0x1c45` if we enter wrong input, and thus it will print us the flag.

So, I exited graph mode by pressing `q` two times. Then, I printed disassembled code of the main function using `pdf @ main` command.

Most of the assembly code wasn't of much importance. All I needed was to find the location where `rax` and `qword [var_1c8h` were being compared.

At location `0x00001c3c` the comparision was being done, and at `0x00001c43` the jump was executed, So, I wrote reverse jump using `wa je 0x1c6e @ 0x00001c43` command.
![7](/thc7.png)

Finally, I can exit the program with `q` command.
Then, I ran the binary with random argument, and boom!, I got the flag in hex format:

```bash
4B5A4357515244434749324853544B594F524C45344D44514A424B455157535A4D455957593654424746424559544B454D524B5536524C504F354957595753454C4959575936535A4B354A464B57544B4C4532564533525148553D3D3D3D3D3D
```
![8](/thc8.png)
Then, decoding the hex gave me base32 encoded string, which after decoding gave base64 string, and finally by base64 decoding that string, I got the final flag.
I used bash to complete the decoding part.
```bash
echo "4B5A4357515244434749324853544B594F524C45344D44514A424B455157535A4D455957593654424746424559544B454D524B5536524C504F354957595753454C4959575936535A4B354A464B57544B4C4532564533525148553D3D3D3D3D3D" | xxd -r -p | base32 -d | base64 -d
```
![9](/thc9.png)
And there is our flag.
`THCon21{U7JGLvXkYskPK07T8J0BVCgYsadTf69F}`  
Hope you learned something!    
Happy Hacking!!
:)
  
> - <cite>seizetheday</cite>
