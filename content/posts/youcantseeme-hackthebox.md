+++
author = "biplavxyz"
date = "2021-06-14"
title = "You Can't C Me - Hackthebox"
+++
Greetings everyone!

This is one of the easy challenges from Hackthebox. I will explain how we can solve this challenge using radare2.
Here, Name of the binary is auth.
First, let's load the binary in debug mode with radare2:
```bash
$ r2 -d ./auth
```
We can list all available strings using `iz` command.
Also let's see the information of binary using `iI` command.
![2](/2.png)
We can see that binary is stripped, but other protection mechanisms like canary is turned off. So, it will be easy for us to get the flag.

Then, we analyze the binary and list all functions using `aaa` and `afl` commands respectively.
We can see there is main function.
![1](/1.png)
Now, we can print disassembled code of main using `pdf @ main`
![3](/3.png) 

We can see that at memory location `0x00401241` `strcmp` function is being called. So basically, it compares two string, and in our case it's comapring our input string with the flag.\
Then, if the result is equal, it jumps to the location `0x00401268` and prints us the flag. 
And, if the result is not equal, the program prints "I said, you can't c me!\n", and exits.

![4](/4.png)

Now, it's best to move to visual panell mode using `v`. You can also setup your owncustom layout in there. Here is a great video if you want to learn about visual panel mode.
>
> <https://www.youtube.com/watch?v=xCYQtvGwXmI>

So, how about we setup a breakpoint right where `strcmp` function is called, and see what strings are on the stack.

We can setup breakpoint with `db 0x00401241` command.
Also we can list all breakpoints with `db` command.
Then we can run the binary with `dc` command, and it will ask us to provide an input, then we can hit enter and it will show us `hit breakpoint at 0x00401241`.

![5](/5.png)
\
\
![6](/6.png)

Then hit enter, and we can see stack, and there is a string that seems like it's in flag format, and obviosuly it's the final flag.
![7](/7.png)

Also, when we click on `rdi` register from registers list, it shows flag on hexdump too.
![8](/8.png)
\
![9](/9.png)

Then we can simply run the program and enter that final string, and we will get final flag.
![10](/10.png)

Hope you learned something today.
Thanks! Keep Learning!  
> - <cite>seizetheday</cite>
