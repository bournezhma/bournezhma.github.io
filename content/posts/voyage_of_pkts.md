+++
title = "A voyage of data packets - originating from the browser and subsequently returning to it"
date = "2023-04-29T00:07:23+08:00"
author = "bournezhma"
authorTwitter = "" #do not include @
cover = "https://media.istockphoto.com/id/171584161/photo/internet-concept.jpg?b=1&s=170667a&w=0&k=20&c=FYb7-RFaHde7w2z1sAGOYBE-ROFVcaXyCSNrSjgJTCA="
tags = ["computer-networking"]
keywords = ["Internet", "Data Packet"]
description = "Using the example of accessing a webpage through a browser, Internet can be explained as protocol, protocol, and more protocols."
showFullContent = false
readingTime = true
toc = true
+++

## Introduction

When people talk about the *Internet*, they are often alluding to websites such as Google or mobile applications like Tiktok. 
However, they are both the services based on Internet instead of Internet itself.
The interesting aspect lies in the fact that individuals' misconceptions regarding the Internet serve to demonstrate one of its fundamental attributes as the backbone of the modern information era - transparency. Without even being cognizant of it, people rely on the Internet incessantly.

So, what is the Internet? In this AI era, we can turn to tools like ChatGPT to help us understand.
The highlighted portion of the answer (from GPT-3.5-turbo on April 29th, 2023) reads as follows:

> *The Internet is a vast infrastructure of interconnected computer networks that communicate with each other using standard protocols.*

This answer correctly notes that the Internet is a internet (with a lowercase "i") of networks, including Ethernet, which are interconnected using standardized protocols. 

> ***Tip:** Internet vs internet*
>
> *The term "Internet" refers to the global network of computer networks that use a common set of protocols and standards to communicate with each other. On the other hand, the term "internet" is a more general term that refers to any two or more computer networks that are connected to each other.*

In the field of communications, a protocol refers to a set of rules and standards that dictate how data is transmitted over a network. These rules determine how the data is formatted, sent, received, and interpreted by the devices on the same network. The purpose of protocols is to ensure that data is delivered consistently and efficiently by defining how devices can communicate and operate seamlessly with one another. Examples of common communication protocols include [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)/[IP](https://en.wikipedia.org/wiki/Internet_Protocol), [HTTP](https://en.wikipedia.org/wiki/HTTP), etc. 

![TCP/IP protocl stack](https://microchipdeveloper.com/local--files/tcpip:tcp-ip-five-layer-model/layer_terminology.JPG "TCP/IP protocl stack" )

All protocols together form the network stack, commonly represented by the [TCP/IP 5-layer model](https://www.wikiwand.com/en/Internet_protocol_suite). In the following content, I will use a example of accessing a webpage with the browser to explain the protocols involved. While the protocols we will encounter in the upcoming example represent only a small portion of the many protocols used on the Internet, they should be sufficient for us to gain a good understanding of this topic.

## Experiment

Let's get our hands dirty! :)
