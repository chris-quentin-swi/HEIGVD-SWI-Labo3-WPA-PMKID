import hashlib
import hmac
from binascii import a2b_hex
from itertools import islice
from scapy.contrib.wpa_eapol import WPA_key
from pbkdf2 import *

from scapy.all import *

if __name__ == '__main__':
    wpa = rdpcap("PMKID_handshake.pcap")
    A = "Pairwise key expansion"
    f = open("wordlist")
    ssid = ""
    APmac=""
    Clientmac =""
    md5 =""
    pmkid=""
    # beacon
    # key_info &3 pour sha1

    for trame in wpa:
        if trame.subtype == 8 and trame.type ==2 and trame.len ==54 and trame.FCfield=="from-DS":
            APmac = a2b_hex(trame.addr2.replace(":", ""))
            Clientmac = a2b_hex(trame.addr1.replace(":", ""))
            pmkid = trame.wpa_key[6:]
            md5 =  trame.key_info & 0x3
            break
    for trame in wpa:
        if trame.subtype == 8 and trame.type == 0:
            if a2b_hex(trame.addr2.replace(":", ""))==APmac:
                ssid = trame.info.decode("utf-8")
                break

    ssid = str.encode(ssid)
    print(ssid,APmac,Clientmac)
    for line in f:
        line = line.replace("\r", "")
        line = line.replace("\n", "")
        passPhrase = str.encode(line)
        pmk = b""

        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        if md5 & 0x1 == 0x1:
            pmk = pbkdf2(hashlib.md5, passPhrase, ssid, 4096, 32)
        else:
            pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)
        iscorrectPmk = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)
        # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK

        if iscorrectPmk.digest()[0:16] == pmkid:
            print("passphrase found ! : ", line)
            break
        print("passphrase tested  : ", line)
    f.close()
