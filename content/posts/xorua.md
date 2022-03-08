+++
date = "2022-03-07"
author = "biplavxyz"
title = "XORUA - UmdCTF 2022"
+++

Greetings!
This writeup is going to be about "XORUA" challenge from UMDCTF - 2022.
XOR Operation is performed on two png files to get the flag.

Name of the challenge was `XORUA`. So, most likely it was related to XOR operation.
We were given two image files with .png extension; `Before.png` and `After.png`.

![1](/xorua1.png)

`Before.png` was a working png file while `After.png` was corrupted.

So, the likely scenario could have been that the orginial image was XORed with something which resulted as corrupted `After.png` file.

As it's a simple XOR operation, it's possible to retrieve that something which was XORed.
Let's understand how `XOR` works:

`XOR BASICS`

`1 xor 0 = 1`

`0 xor 1 = 1`

`0 xor 0 = 0`

`1 xor 1 = 0`



`X xor Y = Z` 

`X xor Z = Y`


In simple words, If `X` is `XOR`ed with `Y` it gives us `Z`.

Now, with `Z` and `X` we can recover `Y` as `X` `XOR` `Z` =`Y`

In our scenario:

`Before.png XOR SOMETHING => After.png` 

That something can be reversed as:

`Before.png XOR After.png => SOMETHING`

I wrote a simple program in Golang that performs the XOR operation on each byte  and writes that slice to a new file.

{{< code language="Go" title="Golang XOR Two Files" id="2" expand="Show" collapse="Hide" isCollapsed="false" >}}
package main

import(
    "fmt"
    "io/ioutil"
    "log"
)

func main(){

    // Reads first file
    b1, err := ioutil.ReadFile("./After.png")
    if err != nil {
        log.Fatal(err)
    }

    // Reads second file
    b2, err := ioutil.ReadFile("./Before.png")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("=============================================")
    // Prints length of both files
    fmt.Println("Length of first file", "=", len(b1))
    fmt.Println("Length of second file", "=", len(b2))

    fmt.Println("=============================================")
    // Checks if the length is equal
    if len(b1) != len(b2){
        log.Fatal("File length not equal")
    }

    // Makes slice of needed size
    sz := len(b1)
    bf := make([]byte, sz)

    // Performs XOR Operation
    fmt.Println("Performing XOR Operation")
    for i := 0; i < sz; i++ {
        bf[i] = b1[i] ^ b2[i]
    }

    fmt.Println("=============================================")
    // Writes to Outfile
    fmt.Println("Writing output to a file")
    err = ioutil.WriteFile("solved.png", bf, 0666)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Written Successfully")

    fmt.Println("=============================================")
}
{{< /code>}}

Running the script creates a new file `Solved.png` which is the needed flag.  


`Demo`  
![2](/xorua.gif)  

Thanks for reading! 

Happy Learning!! :) :) 
