/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-03
   Identifier: APT17 Oct 10
   Reference: https://goo.gl/puVc9q
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT17_Malware_Oct17_1 {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "dc9b5e8aa6ec86db8af0a7aa897ca61db3e5f3d2e0942e319074db1aaccfdc83"
   strings:
      $s1 = "\\spool\\prtprocs\\w32x86\\localspl.dll" fullword ascii
      $s2 = "\\spool\\prtprocs\\x64\\localspl.dll" fullword ascii
      $s3 = "\\msvcrt.dll" fullword ascii
      $s4 = "\\TSMSISrv.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule APT17_Malware_Oct17_2 {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "20cd49fd0f244944a8f5ba1d7656af3026e67d170133c1b3546c8b2de38d4f27"
   strings:
      $x1 = "Cookie: __xsptplus=%s" fullword ascii
      $x2 = "http://services.fiveemotions.co.jp" fullword ascii
      $x3 = "http://%s/ja-JP/2015/%d/%d/%d%d%d%d%d%d%d%d.gif" fullword ascii

      $s1 = "FoxHTTPClient_EXE_x86.exe" fullword ascii
      $s2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.3072" ascii
      $s3 = "hWritePipe2 Error:%d" fullword ascii
      $s4 = "Not Support This Function!" fullword ascii
      $s5 = "Global\\PnP_No_Management" fullword ascii
      $s6 = "Content-Type: image/x-png" fullword ascii
      $s7 = "Accept-Language: ja-JP" fullword ascii
      $s8 = "IISCMD Error:%d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         pe.exports("_foo@0") or
         1 of ($x*) or
         6 of them
      )
}

rule APT17_Unsigned_Symantec_Binary_EFA {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "128aca58be325174f0220bd7ca6030e4e206b4378796e82da460055733bb6f4f"
   strings:
      $s1 = "Copyright (c) 2007 - 2011 Symantec Corporation" fullword wide
      $s2 = "\\\\.\\SYMEFA" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them and pe.number_of_signatures == 0 )
}

rule APT17_Malware_Oct17_Gen {
   meta:
      description = "Detects APT17 malware"
      author = "Florian Roth"
      reference = "https://goo.gl/puVc9q"
      date = "2017-10-03"
      hash1 = "0375b4216334c85a4b29441a3d37e61d7797c2e1cb94b14cf6292449fb25c7b2"
      hash2 = "07f93e49c7015b68e2542fc591ad2b4a1bc01349f79d48db67c53938ad4b525d"
      hash3 = "ee362a8161bd442073775363bf5fa1305abac2ce39b903d63df0d7121ba60550"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NETCLR 2.0.50727)" fullword ascii
      $x2 = "http://%s/imgres?q=A380&hl=en-US&sa=X&biw=1440&bih=809&tbm=isus&tbnid=aLW4-J8Q1lmYBM" ascii

      $s1 = "hWritePipe2 Error:%d" fullword ascii
      $s2 = "Not Support This Function!" fullword ascii
      $s3 = "Cookie: SESSIONID=%s" fullword ascii
      $s4 = "http://0.0.0.0/1" fullword ascii
      $s5 = "Content-Type: image/x-png" fullword ascii
      $s6 = "Accept-Language: en-US" fullword ascii
      $s7 = "IISCMD Error:%d" fullword ascii
      $s8 = "[IISEND=0x%08X][Recv:] 0x%08X %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and (
            pe.imphash() == "414bbd566b700ea021cfae3ad8f4d9b9" or
            1 of ($x*) or
            6 of them
         )
      )
}
