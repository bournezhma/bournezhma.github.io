+++
date = "2022-03-07"
author = "biplavxyz"
title = "Blockchain 1 - Hashcash - UmdCTF 2022"
+++

This writeup is going to be about "Hashcash" challenge from UMDCTF - 2022.  
We were given a ip address and port where we could connect using netcat.  
It had "Hashcash" running there as a feature to prevent spam emails.  
Our goal was to pass the implemented hashcash mechanism to get the flag.  

First of all, let's understand about hashcash.  

`Hashcash` is a proof-of-work system used to limit email spams and can also  
be implemented for other activites.  

Regarding ctf, `hashcash` was implemented to limit spam emails.  
We had to compute the perfect hashcash stamp so that it would pass the validation.  

After opening netcat connection, some information about hashcash is shown:

`ver = 1` ==> This means that the version of hashcash implemented is 1.

`leading zero bits = 20` ==> This means that the leading zero bits should be 20.

`date format = YYMMDD` ==> This describes the date and time format.  

Let's see a sample hashcash header:

`X-Hashcash: 1:20:220222:root@biplav.xyz::McMybZIhxKXu57jd:ckvi`

Here::

`1` => Hashcash version number

`20` => Number of leading zero bits in hashed code

`220222` => Year, Month, and Day in `YYMMDD` format

`root@biplav.xyz` => Data string being transmitted; valid email for our case

`::` => Field for extension which is optional and ignored in version 1

`McMybZIhxKXu57jd` => String of random characters; Base 64 encoded

`ckvi` => Binary counter encoded in Base 64

So, how does it work?

Sender prepares a header, and appends a random counter.  
It then computes `160-bit SHA-1` hash of the header and sends it.  
The `first 20 bits` or `5 bytes` must be zeroes. 

On the receivers' end, `160-bit SHA1-Hash` of the entire string is computed.  
It also checks the date, and if it's not within two days it's considered invalid.  
Also, email address is checked to see if it's one of the valid emails.  

`Pwning Part`

![2](/pownetcat.png)

As we know the hashcat version is `1`, number of leading zero bits is `20`,  
date format is `YYMMDD`, and also there is a list of valid emails that we were  
able to see using netcat connection.  

The goal was to calculate a valid header from this which will generate a `160-bit SHA-1` hash with `5` bytes`(20 bits)`of leading zeroes.

A solution could be something like this:

```
1:20:220307:birch@hashcash.com::/IXgT3uGKANTaDWsmFB5tg==:Z5twZQ==
```

I thought of generating it by bruteforcing it using random numbers, and was able to generate expected SHA-1 hash.  

{{< code language="python" title="Bruteforce Script" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
#!/usr/bin/python3

import os
from hashlib import sha1
import base64

# Generating random numbers to help with bruteforcing
firstpart = base64.b64encode(os.urandom(16))
secondpart = base64.b64encode(os.urandom(4))

# Hash format
hash_ = sha1(b"1:20:220305:birch@hashcash.com::"+firstpart+b":" + secondpart)

# Bruteforced here
while hash_.hexdigest()[:5] != "00000":
    firstpart = base64.b64encode(os.urandom(16))
    secondpart = base64.b64encode(os.urandom(4))
    str = b"1:20:220307:birch@hashcash.com::"+firstpart+b":" + secondpart
    hash_ = sha1(str)

    print(hash_.hexdigest(), firstpart, secondpart, str)

# Prints out the required payload
print()
print("====================================================================")
print("Flag Payload = ", str.decode("utf-8"))
print("Sha1Sum = ", sha1(str).hexdigest())
print("====================================================================")
{{< /code>}}

The script above prints us the required `header` and verifies that there are `5` leading zeroes.  
After submiitting the header to the server using netcat connection, I received the flag.  

`Demo`  
![1](/powhashcash.gif)  


`Flag`   

`UMDCTF{H@sh_c4sH_1s_th3_F@th3r_0f_pr00f_0f_w0rk}`

Thanks for reading!  
Happy Pwning!! :) :) 
