/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-14
   Identifier: TeleBots
*/

/* Rule Set ----------------------------------------------------------------- */

rule TeleBots_IntercepterNG {
   meta:
      description = "Detects TeleBots malware - IntercepterNG"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "5f9fef7974d37922ac91365588fbe7b544e13abbbde7c262fe30bade7026e118"
   strings:
      $s1 = "Usage: %s iface_num\\dump [mode] [w] [-gw] [-t1 ip]" fullword ascii
      $s2 = "Target%d found: %s - [%.2X-%.2X-%.2X-%.2X-%.2X-%.2X]" fullword ascii
      $s3 = "3: passwords + files, no arp poison" fullword ascii
      $s4 = "IRC Joining Keyed Channel intercepted" fullword ascii
      $s5 = "-tX - set target ip" fullword ascii
      $s6 = "w - save session to .pcap dump" fullword ascii
      $s7 = "example: %s 1 1 -gw 192.168.1.1 -t1 192.168.1.3 -t2 192.168.1.5" fullword ascii
      $s8 = "ORACLE8 DES Authorization intercepted" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 4 of them )
}

rule TeleBots_KillDisk_1 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "8246f709efa922a485e1ca32d8b0d10dc752618e8b3fce4d3dd58d10e4a6a16d"
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "-set=06.12.2016#09:30 -est=1410" fullword ascii
      $s4 = "%d.%d.%d#%d:%d" fullword ascii
      $s5 = " /T /C /G " fullword wide
      $s6 = "[-] > %ls" fullword wide
      $s7 = "[+] > %ls" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 4 of them ) or ( 6 of them )
}

rule TeleBots_KillDisk_2 {
   meta:
      description = "Detects TeleBots malware - KillDisk"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "26173c9ec8fd1c4f9f18f89683b23267f6f9d116196ed15655e9cb453af2890e"
   strings:
      $s1 = "Plug-And-Play Support Service" fullword wide
      $s2 = " /c \"echo Y|" fullword wide
      $s3 = "%d.%d.%d#%d:%d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule TeleBots_CredRaptor_Password_Stealer {
   meta:
      description = "Detects TeleBots malware - CredRaptor Password Stealer"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "50b990f6555055a265fde98324759dbc74619d6a7c49b9fd786775299bf77d26"
   strings:
      $s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\GetPAI\\Out\\IE.pdb" fullword ascii
      $s2 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" fullword ascii
      $s3 = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS" fullword ascii
      $s4 = ".\\PAI\\IEforXPpasswords.txt" fullword ascii
      $s5 = "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s6 = "Opera old version credentials" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule TeleBots_VBS_Backdoor_1 {
   meta:
      description = "Detects TeleBots malware - VBS Backdoor"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "eb31a918ccc1643d069cf08b7958e2760e8551ba3b88ea9e5d496e07437273b2"
   strings:
      $s1 = "cmd = \"cmd.exe /c \" + arg + \" >\" + outfile +\" 2>&1\"" fullword ascii
      $s2 = "GetTemp = \"c:\\WINDOWS\\addins\"" fullword ascii
      $s3 = "elseif (arg0 = \"-dump\") Then" fullword ascii
      $s4 = "decode = \"certutil -decode \" + source + \" \" + dest  " fullword ascii
   condition:
      ( uint16(0) == 0x6553 and filesize < 8KB and 1 of them ) or ( all of them )
}

rule TeleBots_VBS_Backdoor_2 {
   meta:
      description = "Detects TeleBots malware - VBS Backdoor"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "1b2a5922b58c8060844b43e14dfa5b0c8b119f281f54a46f0f1c34accde71ddb"
   strings:
      $s1 = "cmd = \"cmd.exe /c \" + arg + \" \" + arg2" fullword ascii
      $s2 = "Dim WMI:  Set WMI = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")" fullword ascii
      $s3 = "cmd = \"certutil -encode -f \" + source + \" \" + dest" fullword ascii
   condition:
      ( uint16(0) == 0x6944 and filesize < 30KB and 1 of them ) or ( 2 of them )
}

rule TeleBots_Win64_Spy_KeyLogger_G {
   meta:
      description = "Detects TeleBots malware - Win64 Spy KeyLogger G"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/4if3HG"
      date = "2016-12-14"
      hash1 = "e3f134ae88f05463c4707a80f956a689fba7066bb5357f6d45cba312ad0db68e"
   strings:
      $s1 = "C:\\WRK\\GHook\\gHook\\x64\\Debug\\gHookx64.pdb" fullword ascii
      $s2 = "Install hooks error!" fullword wide
      $s4 = "%ls%d.~tmp" fullword wide
      $s5 = "[*]Window PID > %d: " fullword wide
      $s6 = "Install hooks ok!" fullword wide
      $s7 = "[!]Clipboard paste" fullword wide
      $s9 = "[*] IMAGE : %ls" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them ) or ( 3 of them )
}
