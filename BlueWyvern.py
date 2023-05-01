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

#import libraries
import argparse
import re

    
#Helper/Utilities functions below


def checkFoundRules(foundStrings, finite_regex_strings):
    #check findings if equal length
    if len(foundStrings) == len(finite_regex_strings):
        return True
    else:
        return False


#custom file read with character escaping
def readTargetFile(filePath):
    strings = []
    #open the file
    with open(filePath, 'r') as targetFile:
        for line in targetFile:
        
            #rebuild the contents making sure special characters are included
            strings.append(escapeString(line.strip()))
            
    #return file contents with escaped characters for scanning
    return strings
    
    
#making sure special characters are preserved for regex
def escapeString(string):
    escapeCharsList = ['.', '^', '$', '*', '+', '?', '{', '}', '[', ']', '\\', '|', '(', ')', '<', '>', '&', '%', '@', '!', ',', '-', '_', '~', '`', '"']
    
    stringBuilder = ""
    
    #iterate through the string provided and add escape characeters
    for char in string:
    
    	#add escape character if it is in our list
        if char in escapeCharsList:
            stringBuilder += '\\'
            
        #add character to the string builder
        stringBuilder += char
        
    #return compiled string
    return stringBuilder


#setup function for appending global regex keywords
def appendGlobalRegex(globalRegexFile):

    #expanding the set of keywords to search for
    keywords = ['Invoke-Expression', 'Invoke-Command', 'Invoke-Item', 'Start-Process',
            'Start-Service', 'Set-Service', 'Stop-Service', 'Enable-PSRemoting',
            'Enable-WSManCredSSP', 'Get-WMIObject', 'Create-Object', 'New-Object',
            'Get-Process', 'Start-Job', 'Invoke-Command', 'Invoke-WmiMethod',
            'Invoke-CimMethod', 'Get-Command', 'Invoke-History', 'Invoke-RestMethod',
            'Invoke-WebRequest', 'Get-WinEvent', 'Write-EventLog', 'Invoke-Item',
            'Invoke-History', 'Get-NetFirewallRule', 'Get-NetAdapter']


    #expanding regex to search for more obfuscated code
    obfuscatedRegexList = [r'\$[\w\d]{1,}=\[[A-Za-z0-9]{2,}\]',
                    r'\$[\w\d]{1,}=\[[A-Za-z0-9]{2,}\](.)',
                    r'[A-Za-z0-9]*(.)\\1{2,}[A-Za-z0-9]*',
                    r'[A-Za-z0-9]*[0-9A-F]{2,}[A-Za-z0-9]*',
                    r'[^A-Za-z0-9]{2,}',
                    r'[A-Za-z0-9]{2,}\]\[\d{1,}',
                    r'\[\d{1,}\]\[\d{1,}']


    #adding regex to detect malicious URLs
    suspiciousRegexList = [r'((https?:\/\/)?[\w-]+(\.[\w-]+)+\.?(:\d+)?(\/\S*)?)']
    suspiciousRegexList.append(r'((http?:\/\/)?[\w-]+(\.[\w-]+)+\.?(:\d+)?(\/\S*)?)')

    #adding regex to detect malicious IP addresses
    suspiciousRegexList.append(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')

    #adding regex to detect malicious domains
    suspiciousRegexList.append(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')

    #adding regex to detect malicious file attachments
    suspiciousRegexList.append(r'[a-zA-Z0-9][a-zA-Z0-9._-]*\.(?:zip|exe|msi|rar)')

    #adding regex to detect malicious executables
    suspiciousRegexList.append(r'[a-zA-Z0-9][a-zA-Z0-9._-]*\.exe')

    #adding regex to detect malicious registry entries
    suspiciousRegexList.append(r'[\w\d]{1,}=.*\\[\w\d]{1,}\\[\w\d]{1,}')
    
    #load user regex rules file for global scanning
    globalRegexList = readTargetFile(globalRegexRuleFile)
    
    #importing keywords and obfuscation definitions
    globalRegexList += keywords
    globalRegexList += obfuscatedRegexList
    globalRegexList += suspiciousRegexList
    
    #return final compiled regex list
    return globalRegexList



#Regex Scanning Methods

def SearchFiniteRegexStrings(finite_regex_strings, targetFile):
    foundStrings = []
    i = 0
    slen = len(finite_regex_strings)
    
    #scanning each line
    for line in targetFile:
    	#finite state machine regex based string search
    	#this will continue to scan the same line, incase we have 1 one liner
        while i < slen and re.search(finite_regex_strings[i], line): 
           foundStrings.append(finite_regex_strings[i])
           
           #increment state to scan for the next regex rule
           i+=1
           
        #if we found everyhing, exit loop
        if i >= slen: break
        
    return foundStrings
    
#perform finite machine scan with user input list, against the target file
def ScanWithfiniteMachine(finite_regex_strings, targetFile):
    foundStrings = SearchFiniteRegexStrings(finite_regex_strings, targetFile)
    return checkFoundRules(foundStrings, finite_regex_strings)

    
#global regex search, takes the user's input_File and regex_file and scans with regex
def ScanGlobalRegex(targetFile, global_regex_rule_file):

    #append builtin keywords to user regex rules
    global_regexList = appendGlobalRegex(global_regex_rule_file)
    
    #perform regex scanning
    regexMatches = []
    regexMatches = re.findall('|'.join(global_regexList), targetFile.read())
    
    #confirm and print findings
    if len(regexMatches) > 0:
        print("Global Regex Matches found:")
        
        #print the results so we can use it later for reference
        for match in regexMatches:
            print(match)
        return True
    else:
        print("No Global Regex matches found.")
    return False
    

    
#perform regex tests, for global rules, and finite machine rules if the rule file is present
def RunTests(args):

    #open input file for testing
    finite_regex_strings = readTargetFile(args.finite_file)
    targetFile = open(args.input_file, "r")
    
    #begin testing
    result = False
    
    #scan with finite state machine if we are given finite rules 
    if args.finite_file != None:
        result = ScanWithfiniteMachine(finite_regex_strings, targetFile)
    
    #scan for global regex if we are given global rules
    if args.regex_file != None:
        result = result or ScanGlobalRegex(targetFile, args.regex_file)
   
    return (result)
    


#used by the main() entry method to validate user inputs
def validateInputArgs(args):

    #check that the input file, and atleast one regex rule file is present
    if args.input_file is None or (args.finite_file is None and args.regex_file is None):
        print("Error: both Input_file and at least 1 Regex file (finite_file or regex_file) must be provided")
        print("False\n")
        return False
    return True


#setup program with user inputs
def main():

    #collect user arguements
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", help="Input file containing the code to be scanned")
    parser.add_argument("--regex_file", help="The file containing the regex strings to use for the scan")
    parser.add_argument("--finite_file", help="The file containing  ordered regex string to use for the scan")
    
    args = parser.parse_args()
    
    #validate user arguements before going any further
    if validateInputArgs(args) == False:
        return
    	
    print (RunTests(args))


#Main entry, validating user inputs and setting up tests to scan the target file

if __name__ == "__main__":
    main()



