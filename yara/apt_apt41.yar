/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2019-08-07
   Identifier: APT41
   Reference: https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html
   License: https://creativecommons.org/licenses/by-nc/4.0/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_APT41_POISONPLUG_3 {
   meta:
      description = "Detects APT41 malware POISONPLUG"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 80
      hash1 = "70c03ce5c80aca2d35a5555b0532eedede24d4cc6bdb32a2c8f7e630bba5f26e"
      id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
   strings:
      $s1 = "Rundll32.exe \"%s\", DisPlay 64" fullword ascii
      $s2 = "tcpview.exe" fullword ascii
      $s3 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" fullword ascii /* reversed goodware string 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' */
      $s4 = "AxEeulaVteSgeR" fullword ascii /* reversed goodware string 'RegSetValueExA' */
      $s5 = "%04d-%02d-%02d_%02d-%02d-%02d.dmp" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 900KB and 3 of them
}

rule APT_APT41_POISONPLUG_SHADOW {
   meta:
      description = "Detects APT41 malware POISONPLUG SHADOW"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 85
      hash1 = "462a02a8094e833fd456baf0a6d4e18bb7dab1a9f74d5f163a8334921a4ffde8"
      id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and pe.imphash() == "c67de089f2009b21715744762fc484e8"
}

rule APT_APT41_CRACKSHOT {
   meta:
      description = "Detects APT41 malware CRACKSHOT"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 85
      hash1 = "993d14d00b1463519fea78ca65d8529663f487cd76b67b3fd35440bcdf7a8e31"
      id = "4ec34a77-dc7f-5f27-9f0a-c98438389018"
   strings:
      $x1 = ";procmon64.exe;netmon.exe;tcpview.exe;MiniSniffer.exe;smsniff.exe" ascii

      $s1 = "RunUrlBinInMem" fullword ascii
      $s2 = "DownRunUrlFile" fullword ascii
      $s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36" fullword ascii
      $s4 = "%s|%s|%s|%s|%s|%s|%s|%dx%d|%04x|%08X|%s|%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 250KB and ( 1 of ($x*) or 2 of them )
}

rule APT_APT41_POISONPLUG_2 {
   meta:
      description = "Detects APT41 malware POISONPLUG"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 70
      hash1 = "0055dfaccc952c99b1171ce431a02abfce5c6f8fb5dc39e4019b624a7d03bfcb"
      id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
   strings:
      $s1 = "ma_lockdown_service.dll" fullword wide
      $s2 = "acbde.dll" fullword ascii
      $s3 = "MA lockdown Service" fullword wide
      $s4 = "McAfee Agent" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and all of them
}

rule APT_APT41_POISONPLUG {
   meta:
      description = "Detects APT41 malware POISONPLUG"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 80
      hash1 = "2eea29d83f485897e2bac9501ef000cc266ffe10019d8c529555a3435ac4aabd"
      hash2 = "5d971ed3947597fbb7e51d806647b37d64d9fe915b35c7c9eaf79a37b82dab90"
      hash3 = "f4d57acde4bc546a10cd199c70cdad09f576fdfe66a36b08a00c19ff6ae19661"
      hash4 = "3e6c4e97cc09d0432fbbbf3f3e424d4aa967d3073b6002305cd6573c47f0341f"
      id = "e150dd69-c611-53de-9c7d-de28d3a208dc"
   strings:
      $s1 = "TSMSISrv.DLL" fullword wide
      $s2 = "[-]write failed[%d]" fullword ascii
      $s3 = "[-]load failed" fullword ascii
      $s4 = "Remote Desktop Services" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and (
         pe.imphash() == "1b074ef7a1c0888ef31337c8ad2f2e0a" or
         2 of them
      )
}

rule APT_APT41_HIGHNOON {
   meta:
      description = "Detects APT41 malware HIGHNOON"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 85
      hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
      hash2 = "4aa6970cac04ace4a930de67d4c18106cf4004ba66670cfcdaa77a4c4821a213"
      id = "6611fb04-7237-52d1-b29f-941c3853aeca"
   strings:
      $x1 = "workdll64.dll" fullword ascii

      $s1 = "\\Fonts\\Error.log" ascii
      $s2 = "[%d/%d/%d/%d:%d:%d]" fullword ascii
      $s3 = "work_end" fullword ascii
      $s4 = "work_start" fullword ascii
      $s5 = "\\svchost.exe" ascii
      $s6 = "LoadAppInit_DLLs" fullword ascii
      $s7 = "netsvcs" fullword ascii
      $s8 = "HookAPIs ...PID %d " fullword ascii
      $s9 = "SOFTWARE\\Microsoft\\HTMLHelp" fullword ascii
      $s0 = "DllMain_mem" fullword ascii
      $s10 = "%s\\NtKlRes.dat" fullword ascii
      $s11 = "Global\\%s-%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) or 4 of them )
}

rule APT_APT41_HIGHNOON_2 {
   meta:
      description = "Detects APT41 malware HIGHNOON"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      hash1 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
      id = "1e48d859-2da9-583e-80e5-8d59054cfb85"
   strings:
      $x1 = "H:\\RBDoor\\" ascii

      $s1 = "PlusDll.dll" fullword ascii
      $s2 = "ShutDownEvent.dll" fullword ascii
      $s3 = "\\svchost.exe" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "b70358b00dd0138566ac940d0da26a03" or
         pe.exports("DllMain_mem") or
         $x1 or 3 of them
      )
}

rule APT_APT41_HIGHNOON_BIN {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 90
      hash1 = "490c3e4af829e85751a44d21b25de1781cfe4961afdef6bb5759d9451f530994"
      hash2 = "79190925bd1c3fae65b0d11db40ac8e61fb9326ccfed9b7e09084b891089602d"
      id = "c8bd62b4-b882-5c04-aace-76dd4a21a784"
   strings:
      $s1 = "PlusDll.dll" fullword ascii
      $s2 = "\\Device\\PORTLESS_DeviceName" wide
      $s3 = "%s%s\\Security" fullword ascii
      $s4 = "%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword ascii
      $s5 = "%s%s\\Enum" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "b70358b00dd0138566ac940d0da26a03" or
         3 of them
      )
}

rule APT_APT41_HIGHNOON_BIN_2 {
   meta:
      description = "Detects APT41 malware HIGHNOON.BIN"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 85
      hash1 = "63e8ed9692810d562adb80f27bb1aeaf48849e468bf5fd157bc83ca83139b6d7"
      hash2 = "c51c5bbc6f59407286276ce07f0f7ea994e76216e0abe34cbf20f1b1cbd9446d"
      id = "37d6a44d-7811-5e87-84e2-b2a8b3da3124"
   strings:
      $x1 = "\\Double\\Door_wh\\" ascii
      $x2 = "[Stone] Config --> 2k3 TCP Positive Logout." fullword ascii
      $x3 = "\\RbDoorX64.pdb" ascii
      $x4 = "RbDoor, Version 1.0" fullword wide
      $x5 = "About RbDoor" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule APT_APT41_RevokedCert_Aug19_1 {
   meta:
      description = "Detects revoked certificates used by APT41 group"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2019/08/apt41-dual-espionage-and-cyber-crime-operation.html"
      date = "2019-08-07"
      score = 60
      id = "f107cc42-58ec-500d-b1c3-27e9e00826aa"
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].serial == "0b:72:79:06:8b:eb:15:ff:e8:06:0d:2c:56:15:3c:35" or
         pe.signatures[i].serial == "63:66:a9:ac:97:df:4d:e1:73:66:94:3c:9b:29:1a:aa" or
         pe.signatures[i].serial == "01:00:00:00:00:01:30:73:85:f7:02" or
         pe.signatures[i].serial == "14:0d:2c:51:5e:8e:e9:73:9b:b5:f1:b2:63:7d:c4:78" or
         pe.signatures[i].serial == "7b:d5:58:18:c5:97:1b:63:dc:45:cf:57:cb:eb:95:0b" or
         pe.signatures[i].serial == "53:0c:e1:4c:81:f3:62:10:a1:68:2a:ff:17:9e:25:80" or
         pe.signatures[i].serial == "54:c6:c1:40:6f:b4:ac:b5:d2:06:74:e9:93:92:c6:3e" or
         pe.signatures[i].serial == "fd:f2:83:7d:ac:12:b7:bb:30:ad:05:8f:99:9e:cf:00" or
         pe.signatures[i].serial == "18:63:79:57:5a:31:46:e2:6b:ef:c9:0a:58:0d:1b:d2" or
         pe.signatures[i].serial == "5c:2f:97:a3:1a:bc:32:b0:8c:ac:01:00:59:8f:32:f6" or
         pe.signatures[i].serial == "4c:0b:2e:9d:2e:f9:09:d1:52:70:d4:dd:7f:a5:a4:a5" or
         pe.signatures[i].serial == "58:01:5a:cd:50:1f:c9:c3:44:26:4e:ac:e2:ce:57:30" or
         pe.signatures[i].serial == "47:6b:f2:4a:4b:1e:9f:4b:c2:a6:1b:15:21:15:e1:fe" or
         pe.signatures[i].serial == "30:d3:c1:67:26:5b:52:0c:b8:7f:25:84:4f:95:cb:04" or
         pe.signatures[i].serial == "1e:52:bb:f5:c9:0e:c1:64:d0:5b:e0:e4:16:61:52:5f" or
         pe.signatures[i].serial == "25:f8:78:22:de:56:d3:98:21:59:28:73:ea:09:ca:37" or
         pe.signatures[i].serial == "67:24:34:0d:db:c7:25:2f:7f:b7:14:b8:12:a5:c0:4d"
      )
}

rule APT_APT41_CN_ELF_Speculoos_Backdoor {
   meta:
      description = "Detects Speculoos Backdoor used by APT41"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://unit42.paloaltonetworks.com/apt41-using-new-speculoos-backdoor-to-target-organizations-globally/"
      date = "2020-04-14"
      score = 90
      hash1 = "6943fbb194317d344ca9911b7abb11b684d3dca4c29adcbcff39291822902167"
      hash2 = "99c5dbeb545af3ef1f0f9643449015988c4e02bf8a7164b5d6c86f67e6dc2d28"
      id = "efe2b368-33af-5382-a5f0-0e7dd7f4dea4"
   strings:
      $xc1 = { 2F 70 72 69 76 61 74 65 2F 76 61 72 00 68 77 2E
               70 68 79 73 6D 65 6D 00 68 77 2E 75 73 65 72 6D
               65 6D 00 4E 41 2D 4E 41 2D 4E 41 2D 4E 41 2D 4E
               41 2D 4E 41 00 6C 6F 30 00 00 00 00 25 30 32 78
               2D 25 30 32 78 2D 25 30 32 78 2D 25 30 32 78 2D
               25 30 32 78 2D 25 30 32 78 0A 00 72 00 4E 41 00
               75 6E 61 6D 65 20 2D 76 }
      
      $s1 = "badshell" ascii fullword
      $s2 = "hw.physmem" ascii fullword
      $s3 = "uname -v" ascii fullword
      $s4 = "uname -s" ascii fullword
      $s5 = "machdep.tsc_freq" ascii fullword
      $s6 = "/usr/sbin/config.bak" ascii fullword
      $s7 = "enter MessageLoop..." ascii fullword
      $s8 = "exit StartCBProcess..." ascii fullword

      $sc1 = { 72 6D 20 2D 72 66 20 22 25 73 22 00 2F 70 72 6F
               63 2F }
   condition:
      uint16(0) == 0x457f and
      filesize < 600KB and
      1 of ($x*) or 4 of them
}
