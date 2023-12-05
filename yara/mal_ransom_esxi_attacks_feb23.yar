/* 
   Combined rules with sigs for attacks on Vmware ESX noticed in Feb 23 and Dec 22
   More rules are included in the FULL THOR Scanner
*/

rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_1 {
   meta:
      description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers - file encrypt.sh"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
      date = "2023-02-04"
      score = 85
      hash1 = "10c3b6b03a9bf105d264a8e7f30dcab0a6c59a414529b0af0a6bd9f1d2984459"
      id = "7178dbe4-f573-5279-a23e-9bab8ae8b743"
   strings:
      $x1 = "/bin/find / -name *.log -exec /bin/rm -rf {} \\;" ascii fullword
      $x2 = "/bin/touch -r /etc/vmware/rhttpproxy/config.xml /bin/hostd-probe.sh" ascii fullword
      $x3 = "grep encrypt | /bin/grep -v grep | /bin/wc -l)" ascii fullword

      $s1 = "## ENCRYPT" ascii fullword
      $s2 = "/bin/find / -name *.log -exec /bin" ascii fullword
   condition:
      uint16(0) == 0x2123 and
      filesize < 10KB and (
         1 of ($x*)
         or 2 of them
      ) or 3 of them
}

rule MAL_RANSOM_ELF_ESXi_Attacks_Feb23_1 {
   meta:
      description = "Detects ransomware exploiting and encrypting ESXi servers"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-14"
      date = "2023-02-04"
      score = 85
      hash1 = "11b1b2375d9d840912cfd1f0d0d04d93ed0cddb0ae4ddb550a5b62cd044d6b66"
      id = "d0a813aa-41f8-57df-b708-18ccb0d7a3e5"
   strings:
      $x1 = "usage: encrypt <public_key> <file_to_encrypt> [<enc_step>] [<enc_size>] [<file_size>]" ascii fullword
      $x2 = "[ %s ] - FAIL { Errno: %d }" ascii fullword

      $s1 = "lPEM_read_bio_RSAPrivateKey" ascii fullword
      $s2 = "lERR_get_error" ascii fullword
      $s3 = "get_pk_data: key file is empty!" ascii fullword

      $op1 = { 8b 45 a8 03 45 d0 89 45 d4 8b 45 a4 69 c0 07 53 65 54 89 45 a8 8b 45 a8 c1 c8 19 }
      $op2 = { 48 89 95 40 fd ff ff 48 83 bd 40 fd ff ff 00 0f 85 2e 01 00 00 48 8b 9d 50 ff ff ff 48 89 9d 30 fd ff ff 48 83 bd 30 fd ff ff 00 78 13 f2 48 0f 2a 85 30 fd ff ff }
      $op3 = { 31 55 b4 f7 55 b8 8b 4d ac 09 4d b8 8b 45 b8 31 45 bc c1 4d bc 13 c1 4d b4 1d }
   condition:
      uint16(0) == 0x457f and
      filesize < 200KB and (
         1 of ($x*)
         or 3 of them
      ) or 4 of them
}

rule APT_PY_ESXi_Backdoor_Dec22 {
   meta:
      description = "Detects Python backdoor found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14"
      score = 85
      id = "f0a3b9b9-0031-5d9f-97f8-70f83863ee63"
    strings:
      $x1 = "cmd = str(base64.b64decode(encoded_cmd), " ascii
      $x2 = "sh -i 2>&1 | nc %s %s > /tmp/" ascii
    condition:
      filesize < 10KB and 1 of them or all of them
}

rule APT_SH_ESXi_Backdoor_Dec22 {
   meta:
      description = "Detects malicious script found on ESXi servers"
      author = "Florian Roth"
      reference = "https://blogs.juniper.net/en-us/threat-research/a-custom-python-backdoor-for-vmware-esxi-servers"
      date = "2022-12-14"
      score = 75
      id = "983ac20c-2e61-5365-8849-b3aeb999f909"
    strings:
      $x1 = "mv /bin/hostd-probe.sh /bin/hostd-probe.sh.1" ascii fullword
      $x2 = "/bin/nohup /bin/python -u /store/packages/vmtools.py" ascii
      $x3 = "/bin/rm /bin/hostd-probe.sh.1"
    condition:
      filesize < 10KB and 1 of them
}

rule MAL_RANSOM_SH_ESXi_Attacks_Feb23_2 {
   meta:
      description = "Detects script used in ransomware attacks exploiting and encrypting ESXi servers"
      author = "Florian Roth"
      reference = "https://dev.to/xakrume/esxiargs-encryption-malware-launches-massive-attacks-against-vmware-esxi-servers-pfe"
      date = "2023-02-06"
      score = 85
      id = "d1282dee-0496-52f1-a2b7-27657ab4df8c"
   strings:
      $x1 = "echo \"START ENCRYPT: $file_e SIZE: $size_kb STEP SIZE: " ascii
   condition:
      filesize < 10KB and 1 of them
}

rule SUSP_ESXiArgs_Endpoint_Conf_Aug23 {
   meta:
      description = "Detects indicators found in endpoint.conf files as modified by actors in the ESXiArgs campaign"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/forums/t/782193/esxi-ransomware-help-and-support-topic-esxiargs-args-extension/page-47"
      date = "2023-08-04"
      score = 75
      id = "3e0b5dbf-7c5b-5599-823a-ce35fbdbe64b"
   strings:
      $a1 = "/client/clients.xml" ascii
      $a2 = "/var/run/vmware/proxy-sdk-tunnel" ascii fullword
      $a3 = "redirect" ascii fullword
      $a4 = "allow" ascii fullword

      $s1 = " local 8008 allow allow"
   condition:
      filesize < 2KB and all of them
}
