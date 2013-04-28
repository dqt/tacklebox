import poplib, email
import sys, os
import logging
from copy import deepcopy
import re
import unicodedata
import argparse
import workerpool

global hasAuth

# Make a global logging object.
x = logging.getLogger("log")
x.setLevel(logging.DEBUG)

# This handler writes everything to a file.
h1 = logging.FileHandler("phishfinder.log")
f = logging.Formatter("%(levelname)s %(asctime)s %(funcName)s %(lineno)d %(message)s")
h1.setFormatter(f)
h1.setLevel(logging.DEBUG)
x.addHandler(h1)

# This handler emails me anything that is an error or worse.
h2 = logging.StreamHandler()
h2.setLevel(logging.DEBUG)
f2 = logging.Formatter("%(levelname)s: %(message)s")
h2.setFormatter(f2)
x.addHandler(h2)



class ImportProxies:
    def fromTxt(self,filename):
        self.filename = filename
        proxyDetails = {}
        proxies = []

        x.info("Opening %s", filename)

        try:
            proxylist = [line.strip() for line in open(self.filename)]
            x.info("%s Opened Successfully", self.filename)
        except Exception, err:
            x.exception(err)
            x.exception("Unable to Open %s", self.filename)
            x.exception("Program Will Exit\n\n")
            sys.exit(1)

        x.info("Parsing %s", self.filename)
        for proxy in proxylist:
            try:
                lineList = proxy.split(':')
                if (len(lineList) < 4):
                    hasAuth = 0
                else:
                    if (len(lineList) == 4):
                        hasAuth = 1
            except Exception, err:
                x.exception(err)
                x.exception("Failed To Parse Proxies! Check Format")
                x.exception("Program Will Exit\n\n")
                sys.exit(1)
            try:
                if (len(lineList) == 2):
                    hasAuth = 0
                    proxyDetails = {"address":lineList[0], "port":lineList[1]}
                    proxies.append(deepcopy(proxyDetails))
                elif (len(lineList) == 4):
                    hasAuth = 1
                    proxyDetails = {"address":lineList[0], "port":lineList[1], "username":lineList[2], "password":lineList[3]}
                    proxies.append(deepcopy(proxyDetails))
                else:
                    x.exception("Failed To Parse Proxies! Check Format")
                    x.exception("Program Will Exit\n\n")
                    sys.exit(1)
            except:
                x.exception("Failed To Parse Proxies! Check Format")
                x.exception("Program Will Exit\n\n")
                sys.exit(1)
        numberOfProxies =len(proxies)
        x.info("%d Proxies Parsed Successfully", numberOfProxies)
        return proxies

class ImportAccounts:
    def fromTxt(self,filename):
        self.filename = filename
        acctDetails = {}
        accounts = []

        x.info("Opening %s", filename)

        try:
            acctlist = [line.strip() for line in open(self.filename)]
            x.info("%s Opened Successfully", self.filename)
        except Exception, err:
            x.exception(err)
            x.exception("Unable to Open %s", self.filename)
            x.exception("Program Will Exit\n\n")
            sys.exit(1)

        x.info("Parsing %s", self.filename)
        for acct in acctlist:
            try:
                lineList = acct.split(':')
            except Exception, err:
                x.exception(err)
                x.exception("Failed To Parse Accounts! Check Format 1")
                x.exception("Program Will Exit\n\n")
                sys.exit(1)
            try:
                if (len(lineList) == 2):
                    acctDetails = {"username":lineList[0], "password":lineList[1]}
                    accounts.append(deepcopy(acctDetails))
                else:
                    x.exception("Failed To Parse Accounts")
                    x.exception("Program Will Exit\n\n")
                    sys.exit(1)
            except:
                x.exception("Failed To Parse Accounts! IDK")
                x.exception("Program Will Exit\n\n")
                sys.exit(1)
        numberOfAccts =len(accounts)
        x.info("%d Accounts Parsed Successfully", numberOfAccts)
        return accounts



class PopTools:
    def __init__(self,username,password,threadCount,popHost,popPort,keyList=None,maxMessages=None):
        self.user = username
        self.password = password
        self.keyList = keyList
        self.maxMessages = maxMessages
        self.threadCount = threadCount
        self.popHost = popHost
        self.popPort = popPort


    def slugify(self,value):
        """
        Normalizes string, converts to lowercase, removes non-alpha characters,
        and converts spaces to hyphens.
        """
        self.value = unicode(value)
        self.value = unicodedata.normalize('NFKD', self.value).encode('ascii', 'ignore')
        self.value = unicode(re.sub('[^\w\s-]', '', self.value).strip().lower())
        self.value = unicode(re.sub('[-\s]+', '-', self.value))
        return self.value



    def extract_body(self,payload):
            if isinstance(payload,str):
                return payload
            else:
                return '\n'.join([self.extract_body(part.get_payload()) for part in payload])


    def parseBody(self):
        x.info("THREAD %s: Started Parsing Message Bodies",self.threadCount)
        self.count = 1
        x.info("THREAD %s: Connecting To Mailbox",self.threadCount)
        Mailbox = poplib.POP3_SSL(self.popHost, self.popPort)
        try:
            Mailbox.user(self.user)
            Mailbox.pass_(self.password)
            x.info("THREAD %s: Connection Successfull!",self.threadCount)
        except:
            x.exception("THREAD %s: Mailbox Authentication Failed!",self.threadCount)
        self.messageCount = len(Mailbox.list()[1])
        x.info ("THREAD %s: %d Total Messages In Mailbox", self.threadCount,self.messageCount)
        if self.maxMessages == 0:
            self.maxMessages = self.messageCount
            x.info("THREAD %s: Parsing All Messages")
        if self.maxMessages >= self.messageCount:
            self.maxMessages = self.messageCount
        else:
            x.info("THREAD %s: Parsing First %d Messages", self.threadCount,self.maxMessages)
        self.to = self.slugify(self.user)
        direct = "/" + self.to
        if not os.path.exists(os.getcwd()+direct):
            os.makedirs(os.getcwd()+direct)
        for i in range(self.maxMessages):

            if showProgress == 1:
                self.no = i
                self.per = (float(self.no)/self.maxMessages)*100
                if self.per > 20 and self.per < 30:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)
                if self.per > 50 and self.per < 60:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)
                if self.per > 70 and self.per < 80:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)
                if self.per > 90 and self.per < 100:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)

            self.raw = Mailbox.retr( i+1 )
            self.message = email.message_from_string('\n'.join(self.raw[1]))
            self.subject = self.message['subject']
            self.payload = self.message.get_payload()
            self.body = self.extract_body(self.payload)
            for self.key in self.keyList:
                if self.body.lower().__contains__(self.key.lower()):
                    sub = str(self.subject)
                    slug = self.slugify(self.subject)
                    self.nameBuilder = self.key + " - "+ slug+".txt"
                    self.name = os.getcwd() + direct + "/" + self.nameBuilder
                    self.doc = open(self.name, 'a')
                    self.doc.write("SUBJECT: " + self.subject + "\nKEY: " + self.key +"\n\n\n")
                    self.doc.write(self.body)
                    self.doc.close
                    self.count+=1



        x.info("THREAD %s: Mailbox Parsing Complete",self.threadCount)
        x.info("THREAD %s: %d Files Saved", self.threadCount,self.count-1)

    def parseBodyRegex(self):
        x.info("THREAD %s: Started Parsing Message Bodies",self.threadCount)
        self.count = 1
        x.info("THREAD %s: Connecting To Mailbox",self.threadCount)
        Mailbox = poplib.POP3_SSL(self.popHost, self.popPort)
        try:
            Mailbox.user(self.user)
            Mailbox.pass_(self.password)
            x.info("THREAD %s: Connection Successfull!",self.threadCount)
        except:
            x.exception("THREAD %s: Mailbox Authentication Failed!",self.threadCount)
            x.exception(err)
        self.messageCount = len(Mailbox.list()[1])
        x.info ("THREAD %s: %d Total Messages In Mailbox", self.threadCount,self.messageCount)
        if self.maxMessages == 0:
            self.maxMessages = self.messageCount
            x.info("THREAD %s: Parsing All Messages")
        if self.maxMessages >= self.messageCount:
            self.maxMessages = self.messageCount
        else:
            x.info("THREAD %s: Parsing First %d Messages", self.threadCount,self.maxMessages)
        self.to = self.slugify(self.user)
        direct = "/" + self.to
        if not os.path.exists(os.getcwd()+direct):
            os.makedirs(os.getcwd()+direct)
        for i in range(self.maxMessages):

            if showProgress == 1:
                self.no = i
                self.per = (float(self.no)/self.maxMessages)*100
                if self.per > 20 and self.per < 30:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)
                if self.per > 50 and self.per < 60:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)
                if self.per > 70 and self.per < 80:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)
                if self.per > 90 and self.per < 100:
                    x.info("THREAD %s: %d%%  Complete", self.threadCount, self.per)

            self.raw = Mailbox.retr( i+1 )
            self.message = email.message_from_string('\n'.join(self.raw[1]))
            self.subject = self.message['subject']
            self.payload = self.message.get_payload()
            self.body = self.extract_body(self.payload)
            for self.key in self.keyList:
                self.reggies = re.findall(self.key,self.body)
                if self.reggies is not None:
                    sub = str(self.subject)
                    slug = self.slugify(self.subject)
                    self.nameBuilder = str(self.count) + " - "+ slug+".txt"
                    self.name = os.getcwd() + direct + "/" + self.nameBuilder
                    self.doc = open(self.name, 'a')
                    self.doc.write("SUBJECT: " + self.subject + "\nREGEX: " + self.key +  "+\n\n")
                    for self.regin in self.reggies:
                        self.doc.write(self.regin  +" \n")
                    self.doc.write("\n\n"+self.body)
                    self.doc.close
                    self.count+=1



        x.info("THREAD %s: Mailbox Parsing Complete",self.threadCount)
        x.info("THREAD %s: %d Files Saved", self.threadCount,self.count-1)



class ParseBodyJob(workerpool.Job):
    def __init__(self,popper):
        self.popper = popper

    def run(self):
        try:
            self.popper.parseBody()
        except:
            x.warning('Thread Failed Trying Next Account')

class ParseBodyRegexJob(workerpool.Job):
    def __init__(self,popper):
        self.popper = popper

    def run(self):
        try:
            self.popper.parseBodyRegex()
        except:
            x.warning('Thread Failed Trying Next Account')



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--strings", help="file containing strings to search",
                    type=str)
    parser.add_argument("-r", "--regex", help="treat keyfile as regex",
                    type=str)
    parser.add_argument("-a", "--accounts", help="file containing account details",
                    type=str)
    parser.add_argument("-m", "--max", help="maximum amount of emails to parse per account (0 if all)",
                    type=int)
    parser.add_argument("-t", "--threads", help="number of threads to use",
                    type=int)
    parser.add_argument("-p", "--progress", help="show progress",
                    action="store_true")
    parser.add_argument("--gmail", help="use gmail account list",
                    action="store_true")
    parser.add_argument("--hotmail", help="use hotmail account list",
                    action="store_true")
    parser.add_argument("--yahoo", help="use yahoo account list",
                    action="store_true")
    parser.add_argument("--custom", help="use custom pop host and port",
                    action="store_true")
    parser.add_argument("-o", '--organize', help="organize account list by type",
                    type=str)
    args = parser.parse_args()



    global showProgress
    showProgress = 0

    if args.progress:
        showProgress = 1



    x.info('Application Started')
    '''
    filename = raw_input("\nName Of Proxy File: ")    #################  DEPRECIATED PROXY  #######################
    str(filename)
    proxyList = ImportProxies().fromTxt(filename)
    proxyType = raw_input("\nType Of Proxies (socks4,socks5,http): ")
    str(proxyType)                                  ##################################################################
    '''



    if args.strings and args.accounts and args.max:
        if args.threads:
            thread = args.threads
        else:
            thread = 1
        acctFile = args.accounts

        if args.gmail:
            popHost = 'pop.googlemail.com'
            popPort = '995'
        elif args.hotmail:
            popHost = 'pop3.live.com'
            popPort = '995'
        elif args.yahoo:
            popHost = 'pop.mail.yahoo.com'
            popPort = '995'
        elif args.custom:
            popHost = raw_input("Enter Host [pop.yourserver.com]: ")
            popPort = raw_input("Enter Port [666]: ")
            str(popHost)
            str(popPort)
        else:
            x.exception("You Must Specify The Account Type!")
            x.info("Program Will Now Exit")
            sys.exit(1)
        try:
            accountList = ImportAccounts().fromTxt(acctFile)
        except Exception, err:
            x.exception("Failed To Parse Account File. Does it exist?")
            x.exception("Program Will Exit")
            x.exception(err)
            sys.exit(1)

        keyFile = args.strings
        try:
            keyList = [line.strip() for line in open(keyFile)]
        except Exception, err:
            x.exception("Failed To Parse Key File. Does it exist?")
            x.exception("Program Will Exit")
            x.exception(err)
            sys.exit(1)
        pool = workerpool.WorkerPool(size=thread)
        threadCount = 1
        totalCount = 0
        for a in accountList:
            try:
                if threadCount > thread:
                    threadCount = 1
                pop = PopTools(a['username'],a['password'],threadCount,popHost,popPort,keyList,args.max)
                job = ParseBodyJob(pop)
                pool.put(job)
                threadCount+=1
                totalCount+=1
            except Exception, err:
                x.warning("Job Failed Using " + a['username'] + ":" + a['password'] )
                x.warning("Skipping Account!")
                x.debug(err)
        pool.shutdown()
        pool.wait()


    elif args.regex and args.accounts and args.max:
        if args.threads:
            thread = args.threads
        else:
            thread = 1
        acctFile = args.accounts

        if args.gmail:
            popHost = 'pop.googlemail.com'
            popPort = '995'
        elif args.hotmail:
            popHost = 'pop3.live.com'
            popPort = '995'
        elif args.yahoo:
            popHost = 'pop.mail.yahoo.com'
            popPort = '995'
        elif args.custom:
            popHost = raw_input("Enter Host [pop.yourserver.com]: ")
            popPort = raw_input("Enter Port [666]: ")
            str(popHost)
            str(popPort)
        else:
            x.exception("You Must Specify The Account Type!")
            x.info("Program Will Now Exit")
            sys.exit(1)
        try:
            accountList = ImportAccounts().fromTxt(acctFile)
        except Exception, err:
            x.exception("Failed To Parse Account File. Does it exist?")
            x.exception("Program Will Exit")
            x.exception(err)
            sys.exit(1)

        keyFile = args.regex

        try:
            keyList = [line.strip() for line in open(keyFile)]
        except Exception, err:
            x.exception("Failed To Parse Key File. Does it exist?")
            x.exception("Program Will Exit")
            x.exception(err)
            sys.exit(1)
        pool = workerpool.WorkerPool(size=thread)
        threadCount = 1
        totalCount = 0
        for a in accountList:
            try:
                if threadCount > thread:
                    threadCount = 1
                pop = PopTools(a['username'],a['password'],threadCount,popHost,popPort,keyList,args.max)
                job = ParseBodyRegexJob(pop)
                pool.put(job)
                threadCount+=1
                totalCount+=1
            except Exception, err:
                x.warning("Job Failed Using " + a['username'] + ":" + a['password'] )
                x.warning("Skipping Account!")
                x.debug(err)
        pool.shutdown()
        pool.wait()

    elif args.organize:
        filename = args.organize
        x.info("Opening %s",filename)
        try:
            masterList = [line.strip() for line in open(filename)]
        except Exception,err:
            x.exception("Could Not Open File!")
            x.exception("System Will Now Exit")
            sys.exit(1)
        x.info("%s Successfully Opened",filename)
        tempList = []
        x.info("Cleaning and Organizing Lists")
        for master in masterList:
            try:
                chk = master.split(':')
                if chk[0] != '' and chk[1] !='':
                    tempList.append(chk)
            except:
                pass
        for t in tempList:
            orig = t
            fil = orig[0].split('@')[1]
            filen = os.getcwd()+ "\\" + fil + '.txt'
            doc = open(filen, 'a')
            doc.write(orig[0]+":"+orig[1]+"\n")
        x.info("Operation Completed Successfully")
        sys.exit(0)




    logging.info('Application Finished')

if __name__ == '__main__':
    main()
