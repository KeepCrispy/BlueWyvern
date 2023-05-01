#BlueWyvern Script
#by RYW 2023

#MIT License

#Copyright (c) 2023 RYW

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

#a simple POC for catching obfuscated powershell code or other malicious things that are sneaked in
#can be retooled for performing code security audits. This is best used with an active file integrity monitoring script. Can be used in conjunction with yara for scan coverage.

#for help
#python3 LinearContentScan.py --help
#
#to use:
#python3 LinearContentScan.py --input_file testCode.txt --finite_file testInput.txt
#
#replace testCode.txt with file you want to scan for
#replace finite_file testInput.txt file with your own customized rules that you want to scan for
#use regex_file for global regex scans
#

import argparse
import re

#expanding the set of keywords to search for
keywords = ['Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Process',
            'Start-Service', 'Set-Service', 'Stop-Service', 'Enable-PSRemoting',
            'Enable-WSManCredSSP', 'Get-WMIObject', 'Create-Object', 'New-Object',
            'Get-Process', 'Start-Job', 'Invoke-Command', 'Invoke-WmiMethod',
            'Invoke-CimMethod', 'Get-Command', 'Invoke-History', 'Invoke-RestMethod',
            'Invoke-WebRequest', 'Get-WinEvent', 'Write-EventLog', 'Invoke-Item',
            'Invoke-Expression', 'Invoke-History', 'Get-NetFirewallRule', 'Get-NetAdapter']


#expanding regex to search for more obfuscated code
obfuscated_regex = [r'\$[\w\d]{1,}=\[[A-Za-z0-9]{2,}\]',
                    r'\$[\w\d]{1,}=\[[A-Za-z0-9]{2,}\](.)',
                    r'[A-Za-z0-9]*(.)\\1{2,}[A-Za-z0-9]*',
                    r'[A-Za-z0-9]*[0-9A-F]{2,}[A-Za-z0-9]*',
                    r'[^A-Za-z0-9]{2,}',
                    r'[A-Za-z0-9]{2,}\]\[\d{1,}',
                    r'\[\d{1,}\]\[\d{1,}']


#adding regex to detect malicious URLs
obfuscated_regex.append(r'((https?:\/\/)?[\w-]+(\.[\w-]+)+\.?(:\d+)?(\/\S*)?)')
obfuscated_regex.append(r'((http?:\/\/)?[\w-]+(\.[\w-]+)+\.?(:\d+)?(\/\S*)?)')

#adding regex to detect malicious IP addresses
obfuscated_regex.append(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')

#adding regex to detect malicious domains
obfuscated_regex.append(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')

#adding regex to detect malicious file attachments
obfuscated_regex.append(r'[a-zA-Z0-9][a-zA-Z0-9._-]*\.(?:zip|exe|msi|rar)')

#adding regex to detect malicious executables
obfuscated_regex.append(r'[a-zA-Z0-9][a-zA-Z0-9._-]*\.exe')

#adding regex to detect malicious registry entries
obfuscated_regex.append(r'[\w\d]{1,}=.*\\[\w\d]{1,}\\[\w\d]{1,}')

#detecting strings that contain multiple instances of the same character
obfuscated_regex.append("[A-Za-z0-9]*(.)\\1{2,}[A-Za-z0-9]*")

#detecting strings that contain hexadecimal characters
obfuscated_regex.append("[A-Za-z0-9]*[0-9A-F]{2,}[A-Za-z0-9]*")

#detecting strings that contain suspicious characters
obfuscated_regex.append("[^A-Za-z0-9]{2,}")

#making sure special characters are preserved for regex
def escapeString(string):
    escapeChars = ['.', '^', '$', '*', '+', '?', '{', '}', '[', ']', '\\', '|', '(', ')', '<', '>', '&', '%', '@', '!', ',', '-', '_', '~', '`', '"']
    escapedString = ""
    for char in string:
        if char in escapeChars:
            escapedString += '\\'
        escapedString += char
    return escapedString
    
#global regex search for keywords
def ScanGlobalRegex(file, regexFile):
    regexList = readFile(regexFile)
    
    #importing keywords and obfuscation definitions
    regexList += keywords
    regexList += obfuscated_regex
    
    matches = []
    matches = re.findall('|'.join(regexList), file.read())
            
    if len(matches) > 0:
        print("Global Regex Matches found:")
        for match in matches:
            print(match)
        return True
    else:
        print("No Global Regex matches found.")
    return False

#custom file read with character escaping
def readFile(fileName):
    strings = []
    with open(fileName, 'r') as file:
        for line in file:
            strings.append(escapeString(line.strip()))
    return strings

def ScanWithfiniteMachine(stringList, file):
    foundStrings = []
    i = 0
    slen = len(stringList)
    for line in file:
    
    	#finite machine regex based string search
        while i < slen and re.search(stringList[i], line): 
           foundStrings.append(stringList[i])
           i+=1
        if i >= slen: break

    if len(foundStrings) == len(stringList):
        return True
    else:
        return False

def validateInputArgs(args):
    if args.input_file is None or (args.finite_file is None and args.regex_file is None):
        print("Error: both Input_file and at least 1 Regex file (finite_file or regex_file) must be provided")
        return False
    return True
    
def RunTests(args):
    stringList = readFile(args.finite_file)
    file = open(args.input_file, "r")
    
    result = False
    if args.finite_file != None:
        result = ScanWithfiniteMachine(stringList, file)
        
    if args.regex_file != None:
        result = result or ScanGlobalRegex(file, args.regex_file)
   
    return (result)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", help="Input file containing the code to be scanned")
    parser.add_argument("--regex_file", help="The file containing the regex strings to use for the scan")
    parser.add_argument("--finite_file", help="The file containing  ordered regex string to use for the scan")
    
    args = parser.parse_args()
    if validateInputArgs(args) == False:
        print("Error: inputs are not valid for testing\n")
        print("False\n")
        return
    	
    
    print (RunTests(args))


if __name__ == "__main__":
    main()
