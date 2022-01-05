+++
author = "biplavxyz"
date = "2021-10-21"
title = "PicoGym-2021 - Writeup - Binary Exploitation - Clutter Overflow"
+++

This writeup is going to be about 'Clutter Overflow' challenge from the binary expoitation category of PicoGym. Radare2, and GDB will be used to solve this challenge.

`Binary Exploitation: Clutter Overflow`  
Running the binary with sample input `testinput` does not affect the program, prints out `code == 0x0`
and `code != 0xdeadbeef`  and simply exits.
![1](/1_co.png)

As the challenge title has the word `overflow` in it, most likely it's a buffer overflow challenge. So, providing large input of `A` character changes the code value. It overflowed.
![2](/2_co.png)  
It can be verified that it's really a buffer overflow vulnerability by adding more `A` characters as an input. It returns `segmentation fault` error when passed such a large input. The `SegFault` error occured because our input overwrote everything including the `return address` and tried to return to `0x41414141` location which does not exist in the memory.    
 
Stack and Exploitation
---------------------------------------------------------------
The given binary can be opened in `radare2` with command `r2 ./chall` or `r2 -d ./chall` to open in debug mode.  
Analysis can be done with `aaaa`, imports can be viewed with `ii` command, and functions can be listed with `afl`.  
![4](/4_co.png)  
We can see `main` function in there. So, `s main` can be used to seek to the main function.  
`pdf` prints disassembly of the `main` function.  
![5](/5_co.png)  
Let's understand how the stack is working here, and how can we overwrite local variable to change the value, and also overwrite the return address so that we can jump to anywhere we want.  

---------------------------------------------
Starting with the Standard Entry Sequence 
--------------------------------------------- 
{{< code language="asm" title="Standard Entry Sequence" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}
push rbp
mov rbp, rsp
sub rsp, 0x110
{{< /code >}}

Here, `rbp` register is pushed onto the stack which saves the value of the base pointer `rbp` . The base pointer `RBP` always points to the base of the stack, and the Stack pointer `RSP` always points to the top of the stack.  
Then, the current value of `rsp` is moved onto `rbp`, meaning the `rbp` also now points to top of the stack.  
Finally, `sub rsp, 0x110` allocates `0x110` bytes on the stack to store the local variables.  
The radare2 command `? 0x110` can be used to print `0x110` in all types, which is equivalent to `272` in decimal.  
![7](/7_co.png)  

![6](/6_co.png)
After this `standard entry sequence`, the instruction `mov qword[var_8h], 0` moves 0 to the value stored at location of `var_8h`.  
As this is 64 bit binary, the local variable `var_8h` and `rbp` are placed in the difference of 8 bytes in the stack.

All of this might seem confusing. So, I  decided to draw the stack layout and show how everything is stored in the stack.

![8](/8_co.jpg) 
----------------------------------------------------------------------------
`Remember: The stack grows from higher memory address to lower memory address` 
------------------------------------------------------------------------------
`Top to bottom` in the above diagram.
    
 First, the `return address` is pushed onto the stack, then `RBP` is stored. Afterwards, `0x110` bytes or `272` bytes in decimal is allocated to store local variables. First `8 bytes` is taken by local variable `var_8h`. So, now we have `272-8 = 264` bytes left on the stack.  

Thus, there is 264 bytes to take character string input using `gets` function call, which will be stored as a character string array.  
As `gets` never checks the length of input, it accepts input of very large length. It is very serious issue, and it is possible to overwrite `variables` and `return addresses` because of this.

But here something feels little bit different!  
As stack grows from higher memory address to lower memory address, the `local variable` is already placed on the address higher than that of the `character array input`. So, how can we overwrite the variable that's in opposite direction of where the stack grows.  
It is because `arrays` grow from `lower memory address` to `higher memory address`.  

So, once our input gets filled up on that remaining 264 bytes space, it starts overwriting everything above it.

--------------------------------
Exploitation
--------------------------------
Now, after understanding all of this, I think exploitation would be very easy. It can be exploited two ways:  
Either by changing the local value to equal to `0xdeadbeef` which gives us the flag,  
Or by changing the `return address` to point to the `memory address` which prints the flag.  
As the remaining size for the input is only `264` bytes, anything beyond that should overflow local variable `var_8h` first as it's right above the character array. 

So, with `264+8` we should be able to change the variable to anything we want. Those `8 bytes` can be set to `0xdeadbeef` so that it will give us the flag.

Or, Another way would be to control the `return address` so that we can jump to anywhere in the program.  
For that, we need `264+8+8=280` bytes. 

I used `gdb` to show what happens to `RBP` when we pass the character input of `273` A's.
As, `264+8=272`, 273 characters should overwrite `RBP` value with one `41` as `A` is equivalent to `41` in hex.

![10](/10_co.png)  

As expected, input of `273 A's` overwrites one `A` at `Rbp`. 
   
Now using same idea, here 264 plus first 8 bytes overwrites `local variable`, and another 8 bytes overwrites `RBP` as the RBP is right above the `local variable` as shown in the stack layout above. 
   
Thus, by writing extra `8 bytes` we can fully overwrite `Rbp` and thus can control the return address of the program. Finally, with `280` bytes of input, our program will be pointing to the return address, so that we can overwrite it with any location where we want to jump in the program. For the purpose of this challenge, jumping to the address where `cat flag.txt` is invoked will give us the flag. 

In `disassembled` code above, it can be seen that `cat flag.txt` is being called at location `0x0040077e`. So, providing `280` bytes of input and adding that memory location will overwrite the return address and thus invoke the `cat flag.txt` command and show us the flag.

I used `pwntools` to create an exploit that displays us the flag.   

{{< code language="python" title="Exploit Payload" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
from pwn import *

#Sets remote host and port
p = remote("mars.picoctf.net", 31890)

#Only one of the payloads below will work at a time

#This overwrites the instruction pointer, jumps to `0x0040077e`, and thus executes `cat flag.txt`
########## Use This or The Other One ###############

payload = b"A"*280 
payload += p64(0x0040077e)

####################################################


#This overwrites the variable to make it equal to "0xdeadbeef", which prints us the flag
######### Use This or The Other One ################

#payload = b"A"*264 
#payload += p64(0xdeadbeef)

####################################################
p.sendline(payload)

p.interactive()
{{< /code >}}

Hope you learned something.  
Thank you so much for reading!  
> - <cite>seizetheday</cite>
 
