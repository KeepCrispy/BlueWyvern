# BlueWyvern

This POC tool is designed to detect a wide range of obfuscated code, including potentially malicious code, and to profile common patterns across multiple files. 

credit goes to Panagiotis Chartas for his [PowerShell-Obfuscation-Bible Research](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)

The tool uses regex to detect a variety of obfuscated code, including suspects of malicious code, malicious URLs, IP addresses, domains, file attachments, executables, and registry entries. It also has the capability of finding common code execution patterns when given multiple sources to profile regex rules, and the finite machine regex-based string search can detect multiple requirements in a single line sweep.

This POC tool can be customized to perform security audits on projects and libraries. It is important to keep the tool lightweight, so it can easily be deployed with minimal setup in a pipeline or deployment environment. Customization is highly recommended before use, such as adding logging and notifications, and it should be used in tandem with a file integrity monitor to add an extra layer of visibility. 

This is part of a write-up I'v done for a deep dive into modern AMSI evasion techniques and how you can protect yourself and your development pipeline/environments. [My Powershell AMSI write-up](https://keepcrispy.github.io/AMSIProj)

----------------------------------------------------------------------------

Usage 

for scanning:

python3 BlueWyvern.py --input_file testCode.txt,testCode2.txt,... --finite_file testrule.txt


for profiling:

python3 BlueWyvern.py --input_file testCode.txt,testCode2.txt,... --output_rule testrule.txt

----------------------------------------------------------------------------

