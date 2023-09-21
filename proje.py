from datetime import datetime 
import re
import nmap
import time
import pymongo
from art import *
class ipscan:
  def __init__(self,ip_address):
    self.ip_address = ip_address
  def validate_ip(self):   
       
    # check number of periods  
    if self.ip_address.count('.') != 3:  
        return 'Invalid Ip address'  
   
    ip_list = list(map(str, self.ip_address.split('.')))  
   
    # check range of each number between periods  
    for element in ip_list:  
        if int(element) < 0 or int(element) > 255 or (element[0]=='0' and len(element)!=1):  
            return 'Invalid IP address'  
   
    return 'Valid_IP_address'  
   
   
      

    
class networkscan():
 
       
  def __init__(self,network):
   
   self.network = network  
   

  def scan(self):
    myclient = pymongo.MongoClient("mongodb://localhost:27017")
    mydb = myclient["tester"]
    mycolletction = mydb["productcheck"]
       
  
    nmScan = nmap.PortScanner()
    
    begin = 1
    end = 1200
    nmScan.scan(self.network, arguments='-sn')
    for host in nmScan.all_hosts():
      print(host)
    ip_liste = ' '.join(nmScan.all_hosts())
    # print(ip_liste)

    nmScan.scan(ip_liste, arguments='-sV',ports='70-80')
    # print(nmScan.scaninfo())
    for ip in nmScan.all_hosts():
      if "tcp" in nmScan[ip]:
        # print(nmScan[ip]['tcp'].keys())
        print("---"*20)
        for port in nmScan[ip]['tcp'].keys():
          if (nmScan[ip]['tcp'][port]['state']) == "open":
           
           mydict = {"Host":ip,"Port":port,"state":(nmScan[ip]['tcp'][port]['state']), "PortName ": (nmScan[ip]['tcp'][port]['name']),"Port Product":(nmScan[ip]['tcp'][port]['product']),"Port Version": (nmScan[ip]['tcp'][port]['version'])}
           result = mycolletction.insert_many([mydict])
           print(mydict)
tprint("CHADDER_NETWORK_SCANNER")     
  
deger = input("CHADDER NETWORK SCANER'A HOŞGELDİNİZ  PRODUCT BY: RECEP DEMİR  .... Network  Taramak istiyorum -1 e bas *******  Host Taramak istyiorum  -2 e bas ")
print("Uygulama Yükleniyor *****")
time.sleep( 3 )

print("Uygulama Yükleniyor *****")
try:
 if deger =="1":
  networkdetails = ( input('lütfen ip giriniz'+": "))
  subnet = str(input("subnet girişi yapınız: "+": "))
  print("Bu Networkü senin için  tarıyorum :) *****")
  time.sleep(3)
  
  baglanti = ipscan(ip_address=str(networkdetails))


  print(baglanti.validate_ip())

  if baglanti.validate_ip() == 'Valid_IP_address':
   baglanti = networkscan(network=(networkdetails+"/"+subnet))
   print(baglanti.scan())
   print("Lütfen Desktek için Bizi takip edin")
  
      #  baglanti = networkscan(network=(networkdetails))
        #print(baglanti.scan())
 elif deger == "2":
  networkdetails = ( input('lütfen ip giriniz'+": "))
  print("Bu Networkü senin için  tarıyorum :) *****")
  time.sleep(3)
  
  baglanti = ipscan(ip_address=str(networkdetails))


  print(baglanti.validate_ip())
  if baglanti.validate_ip() == 'Valid_IP_address':
   baglanti = networkscan(network=(networkdetails))
   print(baglanti.scan())
   print("Lütfen Desktek için Bizi takip edin")
 else:
  print("Lütfen Geçerli ip Adresi girişi Yapınız *** CHADDER NETWORKI SCAN") 
except:
  print("Lütfen Geçerli ip Adresi girişi Yapınız *** CHADDER NETWORKI SCAN") 



