import requests, argparse, json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

Parser = argparse.ArgumentParser(description="Aporlorxl23 Subdomain Scanner Tool")
Parser.add_argument("-d","--domain",dest="Domain",required=True,type=str,help="Please Enter Domain For Subdomain Scan")
Parser.add_argument("-r","--resolvers",dest="Resolvers",required=False,type=bool,help="Subdomain Resolvers Scan")
Parser.add_argument("-t","--thread",dest="ThreadCount",default=25,type=int,help="Please Enter Thread Count")
Parser.add_argument("-s","--ssl",dest="SSL",default=True,type=bool,help="SSL Verification")
Args = Parser.parse_args()

Domain = Args.Domain
ThreadCount = Args.ThreadCount
SSL = Args.SSL
Resolvers = Args.Resolvers
AllSubs = []
AllIp = []

RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[1;34m'
YELLOW='\033[1;33m'

Header = {"User-Agent":"Aporlorxl23/Domporlor.py"}

def Help():
    print(f"{GREEN}[+] Usage{NC}: {BLUE}python3 Domporlor.py{NC} {GREEN}-d{NC} {YELLOW}example.com{NC} {GREEN}-t{NC} {YELLOW}50{NC}")
    exit(0)
def Started():
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(f"{GREEN}[+]{NC} {BLUE}Aporlorxl23/Domporlor.py{NC} {GREEN}Started At{NC} {YELLOW}"+current_time+f"{NC}")
def Stoped():
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(f"{GREEN}[?]{NC} {BLUE}Aporlorxl23/Domporlor.py{NC} {GREEN}Stoped At{NC} {YELLOW}"+current_time+f"{NC}")
def Debug(Text):
    print(f"{GREEN}[+]{NC} {YELLOW}{Text}{NC} {BLUE}Started{NC} {GREEN}!{NC}")
def GetApiKey():
    global VirusTotalKey
    try:
        File = open("Domporlor.api","r")
        AllData = ""
        for Test in File:
            Test = Test.strip()
            AllData += Test
        ApiKeys = json.loads(AllData)
        VirusTotalKey = ApiKeys["Virustotal"]
    except:
        Error("Domporlor.api File Not Found")
        Help()
def VirusTotal():
    if VirusTotalKey != "":
        Debug("Virustotal")
        Url = "https://www.virustotal.com/vtapi/v2/domain/report?apikey="+VirusTotalKey+"&domain="+Domain
        try:
            R = requests.get(Url,headers=Header,verify=SSL)
            Resp = json.loads(R.content)
            Number = 0
            while True:
                try:
                    #print(f"  {GREEN}=>{NC} {BLUE}"+Resp["subdomains"][Number]+f"{NC}")
                    AllSubs.append(Resp["subdomains"][Number])
                    Number += 1
                except:
                    break
            
            if Resolvers:
                Number = 0
                while True:
                    try:
                        #print(f"  {GREEN}=>{NC} {BLUE}"+Resp["resolutions"][Number]["ip_address"]+f"{NC}")
                        AllIp.append(Resp["resolutions"][Number]["ip_address"])
                        Number += 1
                    except:
                        break
        except:
            Error("Connection Error")
            Help()
def Omnisint():
    Debug("Omnisint")
    try:
        Number = 0
        while True:
            Url = "https://sonar.omnisint.io/subdomains/"+Domain+"?page="+str(Number)
            R = requests.get(Url,headers=Header,verify=SSL)
            if R.text.strip() == "null":
                break
            else:
                Resp = json.loads(R.content)
                Number2 = 0
                while True:
                    try:
                        #print(f"  {GREEN}=>{NC} {BLUE}"+Resp[Number2]+f"{NC}")
                        AllSubs.append(Resp[Number2])
                        Number2 += 1
                    except:
                        break
                Number += 1
    except:
        Error("Connection Error")
        Help()
def Sublist3r():
    Debug("Sublist3r")
    try:
        Url = "https://api.sublist3r.com/search.php?domain="+Domain
        R = requests.get(Url,headers=Header,verify=SSL)
        if R.text.strip() == "null":
            return
        else:
            Resp = json.loads(R.content)
            Number = 0
            while True:
                try:
                    AllSubs.append(Resp[Number])
                    Number += 1
                except:
                    break
    except:
        Error("Connection Error")
        Help()
def Alienvault():
    Debug("Alienvault")
    try:
        Url = "https://otx.alienvault.com/api/v1/indicators/domain/"+Domain+"/passive_dns"
        R = requests.get(Url,headers=Header,verify=SSL)
        if '"error": "malformed hostname."' in R.text.strip() or '"passive_dns": []' in R.text.strip():
            return
        else:
            Resp = json.loads(R.content)
            Number = 0
            while True:
                try:
                    AllSubs.append(Resp["passive_dns"][Number]["hostname"])
                    Number += 1
                except:
                    break
    except:
        Error("Connection Error")
        Help()
def Bufferover():
    Debug("Bufferover")
    try:
        Url = "https://dns.bufferover.run/dns?q=."+Domain
        R = requests.get(Url,headers=Header,verify=SSL)
        Resp = json.loads(R.content)
        Number = 0
        while True:
            try:
                IpIndex = Resp["FDNS_A"][Number].index(",")
                AllSubs.append(Resp["FDNS_A"][Number][IpIndex+1:])
                if Resolvers:
                    AllIp.append(Resp["FDNS_A"][Number][0:IpIndex])
                Number += 1
            except:
                break
    except:
        Error("Connection Error")
        Help()
def Hackertarget():
    Debug("Hackertarget")
    try:
        Url = "http://api.hackertarget.com/hostsearch/?q="+Domain
        R = requests.get(Url,headers=Header,verify=SSL)
        Data = []
        Ram = ""
        for i in R.text:
            if str(i) != ",":
                Ram += str(i)
            else:
                Data.append(Ram)
                Ram = ""
        NewData = set(Data)
        SortData = list(NewData)
        for i in SortData:
            AllSubs.append(i)
    except Exception as e:
        print("Connection Error",e)
        Help()
def Error(Text):
    print(f"{RED}[-]{NC} {Text} {GREEN}!{NC}")
def Main():
    Started()
    GetApiKey()
    Omnisint()
    VirusTotal()
    Sublist3r()
    Alienvault()
    Bufferover()
    #Hackertarget()
    NewAllSubs = set(AllSubs)
    SortAllSubs = list(NewAllSubs)
    for Subs in SortAllSubs:
        print(f"{GREEN}  => {NC}{Subs}")
    if Resolvers:
        NewAllIp = set(AllIp)
        SortAllIp = list(NewAllIp)
        for Ip in SortAllIp:
            print(f"{GREEN}  => {NC}{Ip}")
    Stoped()
if __name__ == '__main__':
    Pool = ThreadPoolExecutor(ThreadCount)
    Futures = Pool.submit(Main())
