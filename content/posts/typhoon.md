+++
date = "2022-06-24"
author = "biplavxyz"
title = "TyphoonCon CTF 2022 - Reversing Challenge - KeyGenMe - Radare2 Scripting with R2pipe and Python"
+++

Greetings Everyone!  
This writeup is going to be about `KeyGenme` challenge from TyphoonCon CTF 2022.   
I will be using radare2 to do basic reverse engineering and get idea of the program behavior. Then, I will solve this challenge by doing scripting with `r2pipe`.   

Simply running the binary with `./ctf-challenge` asks for the input and trying `supersecurepassword` as input throws output stating that it's not correct, and we should try again. But, we won't try again entering password here. How about performing some basic reverse enginerring?.Let's do it.  


![1](/tc1.png)  
As usual, we open the given executable file with `radare2` and throw bunch of `A's`.  
It took little bit of time to analyze. So, let's see the total count of functions.  
`aflc` command showed 917 as the function. A big number. 
Let's sort functions in an alphabetical order so that it might be easy to iterate through them.  
`aflsn` sorts those functions alphabetically.  

![2](/tc2.png)
![3](/tc3.png)
![4](/tc4.png)  
Then, following same old habit, it's time to look onto `main` function.
![6](/tc6.png)  
I entered visual panels mode with `v` so that it's easier to look graph and disassembly alongside.  
The first thing that looks interesting is that long base-64 encoded string. 
How about decoding it?  

As it can be seen that first three letters of the base-64 encoded string are `Tml`, the command `iz~Tml` can be used to search for string that has letters `Tml` in it.  
![7](/tc7.png)  

Then, Only the base64 part of the output can be extracted with `iz~Tml~[7]` and it can be piped to `base64 -d` to see the decoded output.  
![decode](/decode.png)  

The message states that there is the name of a band, and the song name inside binary, and we need to find three consecutive words from the lyrics of that song, and replace all the spaces with underscores and submit it as the flag. Pretty Straightforward.  

Now, By looking at the disassembled code, it can be seen that the program is prompting us for the password, then calls the `SHA1()` function, and afterwards there is a point where our input loops 20 times.  
![8](/tc8.png)  

![9](/tc9.png)  

After the loop, the generated data is passed for further checks. It can be also seen that there is a hardcoded hash value `2DC37BAACD58BEDBAA48FBB095E1536728524026`. Our generated hash after 20 times of looping, and the hardcoded hash value are passed to another function. 

So, as `SHA1` hash has a length of `40` and as our input is looped `20` times, and the challenge was named `KeyGenMe`, it seems like that our input is hashed using `SHA1` algorithm, and if it matches the hardcoded hash, the function will return 0 as eax value, and if perform `test eax, eax`, `zero flag` will be set, and that input will be considered valid, and can be submitted as flag to the server.  

![10](/tc10.png)  

How about verifying it further with some debugging?  
As the binary is already loaded in debugging mode, I thought of setting up break up right before the function call that takes the hash generated from our input, and the hardcoded hash. `dcu 0x00400cd3` can be used to `debug continue until that function`.   

![11](/tc11.png)  

![12](/tc12.png)  
The values can be seen on the stack.  
![13](/tc13.png)

Based on the `X-64` calling convention, `RDI` and `RSI` registers should hold first and second arguments to the function call. They can be verified by checking register values with `drr` command.As they don't match, it's not going to be correct password. So, how can we find the correct password?  

If we recall the `base-64` decoded data, it was stated that the name of the band and song is somewhere in the binary. Then analyzing all the functions again gives us two interesting functions `Get_Band_Name` and `Hint`.  
![5](/tc5.png)  



















![14](/tc14.png)
![15](/tc15.png)
![16](/tc16.png)
![17](/tc17.png)

  
When all those characters are combined together, it gives us the flag  
`come_crawling_faster`  

So, I used `r2pipe` to create a script with python which automates all of this debugging process and prints out the flag.

![gif](/typhoon_rev.gif)  

The code used is included below:
{{< code language="python" title="Final R2pipe Script" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}

#!/usr/bin/env python3
import r2pipe
import subprocess as p

#Opens binary with r2pipe, and analyzes it
r = r2pipe.open('./ctf-challenge')



#Analyze the binary
r.cmd('aa')


###########################################################################
#Used for extracting Band Name

target_index = []
target_value = []

for i in range(42, 67):
    target_index.append(str((r.cmd(f'pdf @ sym.Get_Band_Name~:{i}[5]')).strip("\n")))
    target_value.append(((r.cmd(f'pdf @ sym.Get_Band_Name~:{i}[6]')).strip("\n")))

mapped = {target_index[i]: target_value[i] for i in range(len(target_index))}

for k,v in mapped.items():
    print(k,"======>", v)

print("-"*100)


xor_behavior = []
for j in range(67, 102):
    xor_behavior.append(str((r.cmd(f'pdf @ sym.Get_Band_Name~:{j}[6]')).strip("\n")))

while("" in xor_behavior) :
    xor_behavior.remove("")

while("eax" in xor_behavior) :
    xor_behavior.remove("eax")


index_one = []
index_two = []

for i in range(len(xor_behavior)):
    if(i % 2) == 0:
        index_one.append(xor_behavior[i])
    else:
        index_two.append(xor_behavior[i])

print("Band Name is ", end = "")
for i in range(len(index_one)):
    print(chr(int(mapped.get(f'{index_one[i]}'),16) ^ int(mapped.get(f'{index_two[i]}'),16)), end = "")
###############################################################################################
print()



###############################################################################################
# Hint Function
print("-"*100)
print("              Hint Function")
hint = r.cmd('pdf @ sym.Hint')
print(hint)
print("-"*100)


## Using google search that has two letters in between p**p we end up with two songs
## Master of Puppet and Pumping Blood
#Master of Puppet is the correct one

print("-"*100)
print("Song name is Master of Puppets")
print('-'*100)

###############################################################################################
# Lyrics For Master of Puppets

lyrics = """End of passion play, crumbling away
I'm your source of self-destruction
Veins that pump with fear, sucking darkest clear
Leading on your death's construction
Taste me you will see
More is all you need
You're dedicated to
How I'm killing you

Come crawling faster
Obey your master
Your life burns faster
Obey your master
Master

Master of puppets I'm pulling your strings
Twisting your mind and smashing your dreams
Blinded by me, you can't see a thing
Just call my name, 'cause I'll hear you scream
Master
Master
Just call my name, 'cause I'll hear you scream
Master
Master

Needlework the way, never you betray
Life of death becoming clearer
Pain monopoly, ritual misery
Chop your breakfast on a mirror
Taste me you will see
More is all you need
You're dedicated to
How I'm killing you

Come crawling faster
Obey your master
Your life burns faster
Obey your master
Master

Master of puppets I'm pulling your strings
Twisting your mind and smashing your dreams
Blinded by me, you can't see a thing
Just call my name, 'cause I'll hear you scream
Master
Master
Just call my name, 'cause I'll hear you scream
Master
Master

Master, master
Where's the dreams that I've been after?
Master, master
You promised only lies
Laughter, laughter
All I hear or see is laughter
Laughter, laughter
Laughing at my cries

Fix me

Hell is worth all that, natural habitat
Just a rhyme without a reason
Never-ending maze, drift on numbered days
Now your life is out of season
I will occupy
I will help you die
I will run through you
Now I rule you too

Come crawling faster
Obey your master
Your life burns faster
Obey your master
Master

Master of puppets I'm pulling your strings
Twisting your mind and smashing your dreams
Blinded by me, you can't see a thing
Just call my name, 'cause I'll hear you scream
Master
Master
Just call my name, 'cause I'll hear you scream
Master
Master"""

# Creating all 3 word possibilities for the flag.

lyr_arr = lyrics.replace('\n', ' ').lower().split(' ')
possibilities = []

for i in range(len(lyr_arr)):
    possibilities.append("_".join(lyr_arr[i:i+3]))


# Submitting all of them and getting the flag
for f in range(len(possibilities)):
    process = p.Popen(['./ctf-challenge'], stdin=p.PIPE, stdout=p.PIPE, stderr=p.PIPE)
    inputdata = str(possibilities[f]).encode("utf-8")+b"\n"
    stdoutdata,stderrdata = process.communicate(input=inputdata)

    if b"Success!" in stdoutdata:
        print("The flag is: ", stdoutdata[-31:-10].decode())
        exit()


{{< /code>}}

Thanks for reading.   
Hope you liked it.   
Happy Pwning!!
:)
  
> - <cite>CarpeDiem</cite>
