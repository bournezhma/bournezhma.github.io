+++
date = "2022-05-24"
author = "biplavxyz"
title = "Forensics 2 - Golden Persistence - HackTheBox - Cyber Apocalypse CTF 2022: Intergalactic Chase"
+++
Hello everyone!  

This was the second forensics challenge from  HackTheBox Cyber Apocalypse CTF 2022.  
Here, we were given an MS Windows registry file.  
![1](/gp1.png)  

After looking for tools to view windows registry files, I found `regripper` and `fred` are pretty amazing tools.  
In here, I will be using `fred` to extract powershell script out of it, and `reglookup` for dumping registry data quickly.  

Once loaded in `fred`, there was a lot of information, but as the first challenge was related to powershell,  
I tried to search for `powershell` and it ended up with interesting result.  

![2](/gp2.png)  

![3](/gp3.png)  

!!!!! Another interesting powershell script !!!!!  
I copied the value and saved it to a file.  
![4](/gp4.png)  

It was a base64 encoded string.  
So, I decoded that base64 encoded data.  

![5](/gp5.png)  

It resulted as another powershell script, which I saved as `out.ps1`.  

It was another encryption algorithm, but had hardcoded key in there.  
Unfortunately, encrypted data was not within the script, but instead the path to the data was available.  
Whole encrypted string was divided onto multiple chunks and each chunk was read from a different file.  
During decryption process, all of them were concatenated to perform final decryption.  
The lines `62 - 68` perform the above operation.  
![6](/gp6.png)  

As the file path is hardcoded in there, using `regripper` and grepping for every filenames stated above revealed the encrypted data.  
![7](/gp7.png)  

Then, I replaced lines `64 - 68` with those chunks of encrypted data, and made a small change to the script to print decrypted output.  

That gives us the flag `HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}`  


Final Script:  

{{< code language="Powershell" title="Final PowerShell Script" id="1" expand="Show" collapse="Hide" isCollapsed="false" >}}

function encr {
    param(
        [Byte[]]$data,
        [Byte[]]$key
      )

    [Byte[]]$buffer = New-Object Byte[] $data.Length
    $data.CopyTo($buffer, 0)

    [Byte[]]$s = New-Object Byte[] 256;
    [Byte[]]$k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $key[$i % $key.Length];
    }

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $i = $j = 0;
    for ($x = 0; $x -lt $buffer.Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $buffer[$x] = $buffer[$x] -bxor $s[$t];
    }

    return $buffer
}


function HexToBin {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true)
    ]
    [string]$s)
    $return = @()

    for ($i = 0; $i -lt $s.Length ; $i += 2)
    {
        $return += [Byte]::Parse($s.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
    }

    Write-Output $return
}

$enc = [System.Text.Encoding]::ASCII
[Byte[]]$key = $enc.GetBytes("Q0mmpr4B5rvZi3pS")
$encrypted1 = "F844A6035CF27CC4C90DFEAF579398BE6F7D5ED10270BD12A661DAD04191347559B82ED546015B07317000D8909939A4DA7953AED8B83C0FEE4EB6E120372F536BC5DC39"
$encrypted2 = "CC19F66A5F3B2E36C9B810FE7CC4D9CE342E8E00138A4F7F5CDD9EED9E09299DD7C6933CF4734E12A906FD9CE1CA57D445DB9CABF850529F5845083F34BA1"
$encrypted3 = "C08114AA67EB979D36DC3EFA0F62086B947F672BD8F966305A98EF93AA39076C3726B0EDEBFA10811A15F1CF1BEFC78AFC5E08AD8CACDB323F44B4D"
$encrypted4 = "D814EB4E244A153AF8FAA1121A5CCFD0FEAC8DD96A9B31CCF6C3E3E03C1E93626DF5B3E0B141467116CC08F92147F7A0BE0D95B0172A7F34922D6C236BC7DE54D8ACBFA70D1"
$encrypted5 = "84AB553E67C743BE696A0AC80C16E2B354C2AE7918EE08A0A3887875C83E44ACA7393F1C579EE41BCB7D336CAF8695266839907F47775F89C1F170562A6B0A01C0F3BC4CB"
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"
# $enc = [System.Text.Encoding]::ASCII
[Byte[]]$data = HexToBin $encrypted
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
Write-Output $DecryptedString

{{< /code>}}

Hope it was helpful!  
Thank you very much for reading!  
Happy Hunting!! :) :) 
