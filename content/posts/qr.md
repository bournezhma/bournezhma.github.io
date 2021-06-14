+++
date = "2021-06-14"
author = "biplavxyz"
title = "Living QR - THCon CTF"
+++

This was a steganography challenge from THCon CTF where we were given a qr .gif image. When I tried to view it, multiple QR's were being loaded in a few milliseconds gap. 
![1](/qr1.png)
I solved this challenge using imagemagick and zbarimg.  First, I used imagemagick to get all single QR's from the given .gif, and then ran zbarimg to get characters from each file, and when I put all characters together I got the flag. Here's my script:
```bash
#!/bin/bash

# Requires imagemagic and zbarimg

# Use imagemagick to convert the given .gif qr file to 40 single files, and renames them as newfile-1.png newfile-2.png and so on upto newfile-40.png
convert living_QR.gif newfile.png

# Loop that iterates through all files and uses zbarimg to print character from it, then filters only the character for the flag using grep and cut
flag=$(for i in {0..40}
do
        zbarimg newfile-$i.png | grep "QR" | cut -d ":" -f 2
done)
#Removes extra space from the flag and writes the flag to file name living_qr_code_flag
echo $flag | tr -d ' ' >> living_qr_code_flag
#Cleans up all those newfiles that were created by imagemagick
rm -rf newfile-*.png
```
![2](/qr2.png)
That gives us the flag `THCon21{Ba5ukumqmZIVJ2onznXkfY61YS7Cxdi6}`  
Hope you learned something today!  
Thanks for reading!  
Happy Hacking!! :) :) 
