# BlueWyvern
A DevSecOps Security Solution for Detecting and Preventing Obfuscated/Malicious Code

It is designed using Regex to detect obfuscated code that may be used to hide malicious code, which YARA is not designed to detect.

Simple POC tool for catching bad code and simple obfuscation

This is part of a write-up I'm doing for a deep dive into modern AMSI evasion techniques and how you can protect yourself and your development pipeline/environments.

This POC tool can be customized for catching obfuscated powershell codes on your system or in a library. You can probably retool it to do some further code audits. 

It's important to keep it light weight so you can deploy this easily with minimal setup to run in your pipeline or deployment environment.

I highly recommend customizing further before use, such as adding logging and notifications. This is best used in tandem with a file integrity monitor as well to an extra layer of visibility.

Cheers
