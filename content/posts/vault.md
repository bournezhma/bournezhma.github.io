+++
date = "2021-11-24"
author = "biplavxyz"
title = "HackTheBox University CTF 2021 - Reversing Challenge - The Vault - Radare2 Debug Mode and Scripting with R2pipe"
+++

Greetings Everyone!  
This writeup is going to be about `The Vault` challenge from HackTheBox University Ctf 2021.  
I will be using radare2 to do basic reverse engineering and solve this challenge.  
At the end, I will use `r2pipe` to automate the whole process.  

Simply running the binary with `./vault` exits by showing the error message `Could not find credentials`  

![1](/rev1.png)
  
Then, I used command `rabin2 -z vault | less` to see all the available strings.  
`flag.txt` was the first string in there. So, I thought that the binary needs to read `flag.txt` to proceed.  
![3](/rev3.png)  
Then, I created a `flag.txt` file with some random characters inside there.  
The resulting output, this time was different.  
![2](/rev2.png)
  
The program printed `Incorrect Credentials - Anti Intruder Sequence Activated...` and terminated.  

Then, I decided to use `radare2` for more deeper analysis.  
The binary can be opened in r2 with `r2 -d ./vault`, analyzed with `aaaa`, and all available functions can be listed with `afl`.  
  
As `main` function is in there, we can seek there with `s main`.  
Disassembled code of `main` function can be printed with `pdf @ main`. 
   
![4](/rev4.png)  

Another function call can be seen there. In our case, `fcn.0000c220` is being called.  
Seeking to that function can be done with `s fcn.0000c220`, and it's disassembled code can be printed with `pdf`.  
  
![5](/rev5.png)

The code seemed very different to me.  I looked up all the symbols with command `iS` and found words like `type_info` there. It basically stores information about a type and can be used to compare two types or to retrieve information 
identifying a type.
    
![10](/rev8.png)
  
Also, running `av` command showed lot of vtables being used.  So, this program was intentionally made quite complicated by using `C++ virtual functions`.  
  
![11](/rev9.png)
  
Then, I thought of viewing decompiled code of it using ghidra's decompiler.     
If `r2ghidra` plugin is installed in radare2, `pdg` command can be used to print the decompiled code which is more easier to understand.  
  
![6](/rev6.png)
  
After checking decompiled code, it can be seen that the binary checks if `flag.txt` is present or not.  
If it's not present, it exits the program, but if it's present then the program enters while loop.  
When any comparision between each and every bytes of `var_211h` and `uVar2` results in false, it sets `bVar1` to `false` and the program exits, and when all bytes always evaluate to `true`, it shows `Credentials Accepted...`.  
  
![7](/rev7.png)
  
But, this is not a simple string comparision where each bytes are compared.  
Everytime, the value of `uVar2` variable is being set in this line  
`uVar2 = (****(*(var_22eh._2_4_ + 0xe090) * 8 + 0x17880))();`    

Each time, It's pointing to a certain virtual function address, which has the corresponding characters for the flag.  

There might be a way to solve this challenge by doing more in-depth analysis about `vtables`, and `RTTI`, but I solved this challenge by setting up a break point at the function, and checking the values printed in the stack.

For every comparision, a value will be printed and it can be clearly seen in the stack.  
Stepping over multiple times through the loop, and combining all values gives us the final flag. 
 
Here is an example of how the values are being printed in the stack. 
Also, I'm pressing `F8` key multiple times to step over the instructions.   
  
![8](/flag_vtables.gif)
  
When all those characters are combined together, it gives us the flag  
`HTB{vt4bl3s_4r3_c00l_huh}`  

It's quite tedious to keep on pressing `F8` key multiple times, and later combine all of the characters to print out the flag.  
So, I used `r2pipe` to create a script with python which automates all of this debugging process and prints out the flag.

![9](/flag_r2pipe.gif)  

The code used is included below:
```python
#!/usr/bin/python3
import r2pipe

#Opens binary with r2pipe in debug mode, and analyzes it
r = r2pipe.open('./vault')

flag = ""

#Enter debug mode and analyze the binary
r.cmd('doo;aaaaa')

#Find the target function where we will be stepping over until we hit the breakpoint
target_func = r.cmd('pdf @ main~[4]~:4')

print("[+] ----------------------------------------------- [+]")
print(f"          Target functions is {target_func}")
print("[+] ----------------------------------------------- [+]")

#Set breakpoint at that target function and step over to find first character 'H'
r.cmd(f'dcu {target_func}')
r.cmd('dso 65')

#Append the character 'H' to the flag
flag += r.cmd('px 6 @ rsp~[4]~:1 | tail -c 2').strip('\n')

#Iterate 24 times to print remaining 24 characters of the flag
for i in range(24):
    r.cmd('dso 45')
    flag += r.cmd('px 20 @ rsp~[3]~:2 | tail -c 2').strip('\n')
print("[+] ----------------------------------------------- [+]")
print("              "+flag)
print("[+] ----------------------------------------------- [+]")
```
Thanks for reading.   
Hope you liked it.   
Happy Pwning!!
:)
  
> - <cite>CarpeDiem</cite>
