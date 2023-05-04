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
import os

    
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

#find common regex pattern algorithm
def FindCommonExecutionPattern(s1, s2): 
  
    m = len(s1) 
    n = len(s2) 
  
    # declaring the array for storing the dp values 
    L = [[None]*(n+1) for i in range(m+1)] 
  
    """Following steps build L[m+1][n+1] in bottom up fashion 
    Note: L[i][j] contains length of LCS of X[0..i-1] 
    and Y[0..j-1]"""
    for i in range(m+1): 
        for j in range(n+1): 
            if i == 0 or j == 0 : 
                L[i][j] = 0
            elif s1[i-1] == s2[j-1]: 
                L[i][j] = L[i-1][j-1]+1
            else: 
                L[i][j] = max(L[i-1][j] , L[i][j-1]) 
  
    # L[m][n] contains the length of LCS of X[0..n-1] & Y[0..m-1] 
    index = L[m][n] 
  
    # Create a character array to store the common string 
    lcs = [""] * (index+1) 
    lcs[index] = "" 
  
    # Start from the right-most-bottom-most corner and 
    # one by one store characters in lcs[] 
    i = m 
    j = n 
    while i > 0 and j > 0: 
  
        # If current character in X[] and Y are same, then 
        # current character is part of common pattern 
        if s1[i-1] == s2[j-1]: 
            lcs[index-1] = s1[i-1] 
            i-=1
            j-=1
            index-=1
  
        # If not same, then find the larger of two and 
        # go in the direction of larger value 
        elif L[i-1][j] > L[i][j-1]: 
            i-=1
        else: 
            j-=1
  
    # Return the common pattern as a string 
    return "".join(lcs) 
  

#setup function for appending global regex keywords
def builtinGlobalRegexScan(targetFile):

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
    globalRegexList = []
    
    
    #importing keywords and obfuscation definitions
    globalRegexList += keywords
    globalRegexList += obfuscatedRegexList
    globalRegexList += suspiciousRegexList
    
    
    #perform regex scanning
    regexMatches = []
    regexMatches = re.findall('|'.join(globalRegexList), targetFile.read())
    
    #confirm and print findings
    if len(regexMatches) > 0:
        print("Builtin Regex Matches found:")
        
        #print the results so we can use it later for reference
        for match in regexMatches:
            print(match)
        return True
    else:
        print("No Builtin Regex matches found.")
    return False

#Write regex rules to a file
def SaveProfileRules(regex_rule, rule_file_name):
    # write regex rule to file with 
    rule_file = open(rule_file_name,'w')
    for rule in regex_rule:  rule_file.write(rule + '\n')

#Regex rule scanning

def ProfileRulesFromFile(targetFile):

    #open the script you want to profile for 
    target_File = open(targetFile, "r")
    script_lines = target_File.readlines()
 
    #create list to store special characters 
    special_characters = []  
    
    #loop through each line of the script 
    for line in script_lines:  
        # split each line into a list of characters  
        for char in line:   
            # check if character is special character   
            if char in ['$', '{', '}', '(', ')', '[', ']', '?', '|', '+', '*', '.', '^', '\\', '<', '>', '&', '=']:    
                # add character to list of special characters    
                special_characters.append(char)

    regex_rule = [] # create regex rule for special characters

    #ceate the regex rule with the detected characters
    for char in special_characters:
        regex_rule.append(char) 
    
    return regex_rule

#Perform rule profiling for all files
def ProfileRulesFromFiles(inputFileList, rule_file_name):
    #holder for all rules
    parsed_rules = []
    
    #iterate through files list provided by user input
    for inputFile in inputFileList:
        #generate rules
        rule = ProfileRulesFromFile(inputFile)
        #add to list of rules
        parsed_rules.append(rule)
    
    if len(parsed_rules)==1:
        SaveProfileRules(parsed_rules[0],rule_file_name)
    elif len(parsed_rules)==0:
        #case for text file without any special characters
        print("no special characters found for profiling")
    
    #at this point, the parsed rules array size must be at least 2
    
    #sort the list in ascending order of length
    #we want the shortest first as our base case
    parsed_rules.sort(key = len)
    
    #the set of common rules, start with the shortest pattern
    common_rules = parsed_rules[0]
    
    listLen = len(parsed_rules) #cache array length for faster performance
    
    #loop through and compare for common regex patterns
    for i in range(1,listLen):
        #compare the common set with the one in the array, re-assign common set with new set
        #this list should only get shorter
        common_rules = FindCommonExecutionPattern(common_rules, parsed_rules[i])
    
    #store final set of commonrules
    SaveProfileRules(parsed_rules[0],rule_file_name)
    
    print("done profiling")

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

    #load user regex rules file for global scanning
    globalRegexList = readTargetFile(globalRegexRuleFile)
    
    #perform regex scanning
    regexMatches = []
    regexMatches = re.findall('|'.join(globalRegexList), targetFile.read())
    
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
        
    result = builtinGlobalRegexScan(targetFile) or result
   
    return (result)
    


#used by the main() entry method to validate user inputs
def validateInputArgs(args):

    #check that the input file, and atleast one regex or rule file is present
    if args.input_file is None or (args.output_rule is None and args.finite_file is None and args.regex_file is None):
        print("Error: both Input_file and at least 1 Regex file (finite_file or regex_file) must be provided")
        print("False\n")
        return False
        #check that input files exist
        
    if not os.path.exists(args.input_file):
        print('Error: the input file does not exist')
        print("False\n")
        return False
    
    #check that finite file exists
    if args.finite_file and not os.path.exists(args.finite_file):
        print('Error: the finite file does not exist')
        print("False\n")
        return False
    
    #check that regex file exists
    if args.regex_file and not os.path.exists(args.regex_file):
        print('Error: the regex file does not exist')
        print("False\n")
        return False

    #check that input file is a valid text file
    if os.path.splitext(args.input_file)[1] not in ['.txt']:
        print('Error: the input file must be a valid text file')
        print("False\n")
        return False
    
    #check that finite file is a valid text file
    if args.finite_file and os.path.splitext(args.finite_file)[1] not in ['.txt']:
        print('Error: the finite file must be a valid text file')
        print("False\n")
        return False

    #check that regex file is a valid text file
    if args.regex_file and os.path.splitext(args.regex_file)[1] not in ['.txt']:
        print('Error: the regex file must be a valid text file')
        print("False\n")
        return False
    
    #check that the input file and output rule is present
    if args.output_rule and os.path.splitext(args.output_rule)[1] not in ['.txt']:
        print('Error: the output rule file must be a valid text file')
        print("False\n")
        return False
        

    #if everything passes, return true
    return True


#setup program with user inputs
def main():

    #collect user arguements
    parser = argparse.ArgumentParser()
    parser.add_argument("--input_file", help="Input files containing the code to be scanned, seperated by commas")
    parser.add_argument("--regex_file", help="The file containing the regex strings to use for the scan")
    parser.add_argument("--finite_file", help="The file containing  ordered regex string to use for the scan")
    parser.add_argument("--output_rule", help="The output rule file from profiling the input file")
    
    args = parser.parse_args()
    
    #split the input files argument into a list
    inputFileList = args.input_file.split(",")
    
    #validate user arguements before going any further
    if validateInputArgs(args) == False:
        return
        
    #check that the input file and output rule is present
    if args.input_file and args.output_rule:
        ProfileRulesFromFile(inputFileList, args.output_rule)
        return
    	
    #iterate through the list of files
    for inputFile in inputFileList:
        #set the input_file argument to the current file
        args.input_file = inputFile
        #run the tests
        print(RunTests(args))


#Main entry, validating user inputs and setting up tests to scan the target file

if __name__ == "__main__":
    main()



