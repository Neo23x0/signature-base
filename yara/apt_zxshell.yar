
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-08
   Identifier: ZxShell Related Malware (same C2)
   Reference: https://blogs.rsa.com/cat-phishing/
*/

/* Rule Set ----------------------------------------------------------------- */

rule ZxShell_Related_Malware_CN_Group_Jul17_1 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "ef56c2609bc1b90f3e04745890235e6052a4be94e35e38b6f69b64fb17a7064e"
   strings:
      $x1 = "CMD.EXE /C NET USER GUEST /ACTIVE:yes && NET USER GUEST ++++++" ascii
      $x2 = "system\\cURRENTcONTROLSET\\sERVICES\\tERMSERVICE" fullword ascii
      $x3 = "\\secivreS\\teSlortnoCtnerruC\\METSYS" fullword ascii /* reversed goodware string 'SYSTEM\\CurrentControlSet\\Services\\' */
      $x4 = "system\\cURRENTCONTROLSET\\cONTROL\\tERMINAL sERVER" fullword ascii
      $x5 = "sOFTWARE\\mICROSOFT\\iNTERNET eXPLORER\\mAIN" fullword ascii
      $x6 = "eNABLEaDMINtsREMOTE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_2 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "204273675526649b7243ee48efbb7e2bc05239f7f9015fbc4fb65f0ada64759e"
   strings:
      $u1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $u2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $u3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
      $u4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii

      $x1 = "\\\\%s\\admin$\\g1fd.exe" fullword ascii
      $x2 = "C:\\g1fd.exe" fullword ascii
      $x3 = "\\\\%s\\C$\\NewArean.exe" fullword ascii
      $x4 = "at \\\\%s %d:%d %s" fullword ascii

      $s1 = "%c%c%c%c%ccn.exe" fullword ascii
      $s2 = "hra%u.dll" fullword ascii
      $s3 = "Referer: http://%s:80/http://%s" fullword ascii
      $s5 = "Accept-Language: zh-cn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 3 of them )
}

rule ZxShell_Related_Malware_CN_Group_Jul17_3 {
   meta:
      description = "Detects a ZxShell related sample from a CN threat group"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "2e5cf8c785dc081e5c2b43a4a785713c0ae032c5f86ccbc7abf5c109b8854ed7"
   strings:
      $s1 = "%s\\nt%s.dll" fullword ascii
      $s2 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}

rule ZxShell_Jul17 {
   meta:
      description = "Detects a ZxShell - CN threat group"
      author = "Florian Roth"
      reference = "https://blogs.rsa.com/cat-phishing/"
      date = "2017-07-08"
      hash1 = "5d2a4cde9fa7c2fdbf39b2e2ffd23378d0c50701a3095d1e91e3cf922d7b0b16"
   strings:
      $x1 = "zxplug -add" fullword ascii
      $x2 = "getxxx c:\\xyz.dll" fullword ascii
      $x3 = "downfile -d c:\\windows\\update.exe" fullword ascii
      $x4 = "-fromurl http://x.x.x/x.dll" fullword ascii
      $x5 = "ping 127.0.0.1 -n 7&cmd.exe /c net start %s" fullword ascii
      $x6 = "ZXNC -e cmd.exe x.x.x.x" fullword ascii
      $x7 = "(bind a cmdshell)" fullword ascii
      $x8 = "ZXFtpServer 21 20 zx" fullword ascii
      $x9 = "ZXHttpServer" fullword ascii
      $x10 = "c:\\error.htm,.exe|c:\\a.exe,.zip|c:\\b.zip\"" fullword ascii
      $x11 = "c:\\windows\\clipboardlog.txt" fullword ascii
      $x12 = "AntiSniff -a wireshark.exe" fullword ascii
      $x13 = "c:\\windows\\keylog.txt" fullword ascii
   condition:
      ( filesize < 10000KB and 1 of them ) or 3 of them
}
