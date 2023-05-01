# BlueWyvern
A Security Solution for Detecting Obfuscated Code for Code Security Audits

credit goes to Panagiotis Chartas for his [PowerShell-Obfuscation-Bible Research](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)

It uses Regex to detect a variety of obfuscated code, including malicious code. It also includes regular expressions to detect malicious URLs, IP addresses, domains, file attachments, executables, and registry entries, which is not possible with Yara's obfuscation rules. Additionally, the finite machine regex-based string search can detect multiple strings in a single line, making it more efficient than Yara's rules.

This is part of a write-up I'v done for a deep dive into modern AMSI evasion techniques and how you can protect yourself and your development pipeline/environments. [My Powershell AMSI write-up](https://keepcrispy.github.io/AMSIProj)

This POC tool can be customized for performing security audits on a project or in a library. 

It's important to keep it light weight so you can deploy this easily with minimal setup to run in your pipeline or deployment environment.

I highly recommend customizing further before use, such as adding logging and notifications. This is best used in tandem with a file integrity monitor as well to add an extra layer of visibility.

Cheers
