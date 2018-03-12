/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-09
   Identifier: Slingshot APT
   Reference: https://securelist.com/apt-slingshot/84312/
*/

import "pe"

rule Slingshot_APT_Spork_Downloader {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
   strings:
      $s1 = "Usage: spork -c IP:PORT" fullword ascii wide
      $s2 = "connect-back IP address and port number"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Slingshot_APT_Minisling {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
   strings:
      $s1 = "{6D29520B-F138-442e-B29F-A4E7140F33DE}" fullword ascii wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Slingshot_APT_Ring0_Loader {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
   strings:
      $s1 = " -> Missing element in DataDir -- cannot install" ascii
      $s2 = " -> Primary loader not present in the DataDir" ascii
      $s3 = "\\\\.\\amxpci" fullword ascii
      $s4 = " -> [Goad] ERROR in CreateFile:" fullword ascii
      $s5 = "\\\\.\\Sandra" fullword ascii
      $s6 = " -> [Sandra] RingZeroCode" fullword ascii
      $s7 = " -> [Sandra] Value from IOCTL_RDMSR:" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Slingshot_APT_Malware_1 {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
      hash1 = "4b250304e28648574b441831bf579b844e8e1fda941fb7f86a7ea7c4291bbca6"
   strings:
      $s1 = "SlingDll.dll" fullword ascii
      $s2 = "BogusDll." ascii
      $s3 = "smsvcrt -h 0x%p" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and (
        pe.imphash() == "7ead4bb0d752003ce7c062adb7ffc51a" or
        pe.exports("WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW0000") or
        1 of them
      )
}

rule Slingshot_APT_Malware_2 {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
      hash1 = "2a51ef6d115daa648ddd57d1e4480f5a18daf40986bfde32aab19349aa010e67"
   strings:
      $x1 = "\\\\?\\c:\\RECYCLER\\S-1-5-21-2225084468-623340172-1005306204-500\\INFO5" fullword wide
      $x_slingshot = {09 46 BE 57 42 DD 70 35 5E }

      $s1 = "Opening service %s for stop access failed.#" fullword wide
      $s2 = "LanMan setting <%s> is ignored because system has a higher value already." fullword wide
      $s3 = "\\DosDevices\\amxpci" fullword wide
      $s4 = "lNTLMqSpPD" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 4 of them )
}

rule Slingshot_APT_Malware_3 {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
      hash1 = "fa513c65cded25a7992e2b0ab03c5dd5c6d0fc2282cd64a1e11a387a3341ce18"
   strings:
      $a1 = "chmhlpr.dll" fullword ascii
      $s2 = "%hc%hc%hc%hc" fullword ascii
      $s3 = "%hc%hc%hc=" fullword ascii
      $s4 = "%hc%hc==" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
        pe.imphash() == "2f3b3df466e24e0792e0e90d668856bc" or
        pe.exports("dll_u") or
        ( $a1 and 2 of ($s*) )
      )
}

rule Slingshot_APT_Malware_4 {
   meta:
      description = "Detects malware from Slingshot APT"
      author = "Florian Roth"
      reference = "https://securelist.com/apt-slingshot/84312/"
      date = "2018-03-09"
      hash1 = "38c4f5320b03cbaf5c14997ea321507730a8c16906e5906cbf458139c91d5945"
   strings:
      $x1 = "Ss -a 4104 -s 257092 -o 8 -l 406016 -r 4096 -z 315440" fullword wide

      $s1 = "Slingshot" fullword ascii
      $s2 = "\\\\?\\e:\\$Recycle.Bin\\" wide
      $s3 = "LineRecs.reloc" fullword ascii
      $s4 = "EXITGNG" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         $x1 or 2 of them
      )
}
