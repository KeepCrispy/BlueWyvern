# BlueWyvern

This POC file integretiy monitoring tool is designed to mainly detect code execution patterns in obfuscated code, catching potentially malicious code, and to profile common patterns across multiple script/files. 

credit goes to Panagiotis Chartas for his [PowerShell-Obfuscation-Bible Research](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)

This POC tool uses regex to detect code execution patterns, including suspects of malicious code, malicious URLs, IP addresses, domains, file attachments, and hidden executable calls. It also has the capability of finding common code execution patterns when given multiple sources to profile regex rules, and the finite machine regex-based string search can detect multiple requirements in a single line sweep. 

This POC tool can be customized to perform some basic security audits on projects and libraries. Like flagging suspects of vulnerable code that may lead to a vulnerability in the application. It is important to keep the tool and rules lightweight, so it can easily be deployed with minimal setup in a pipeline or testing/deployment environment. Customization is highly recommended before use, such as adding logging and notifications.

This is part of a write-up I wrote on modern AMSI evasion techniques and how you can protect yourself and your development pipeline/environments. [My Powershell AMSI write-up](https://keepcrispy.github.io/AMSIProj)

Utimately AMSI systems should be patched to catch these types of issues.

----------------------------------------------------------------------------

This tool has 3 usage modes: Active Scanning (specific files with specific rules), Profiling (pattern finding in files), and Monitoring (File Integrity Monitoring mode)

Usage 

for scanning:

python3 BlueWyvern.py --input_file testCode.txt,testCode2.txt,... --finite_file testrule.txt

for profiling:

python3 BlueWyvern.py --input_file testCode.txt,testCode2.txt,... --output_rule testrule.txt

for monitoring:

python3 BlueWyvern.py --mon_dir /folder/path/you want to/monitor/ [--finite_file testrule.txt]

----------------------------------------------------------------------------

