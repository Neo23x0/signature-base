
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-04
   Identifier: FireEye EternalBlue - Non-Wannacry Attacks
   Reference: https://goo.gl/OOB3mH
*/

/* Rule Set ----------------------------------------------------------------- */

rule Backdoor_Redosdru_Jun17 {
   meta:
      description = "Detects malware Redosdru - file systemHome.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/OOB3mH"
      date = "2017-06-04"
      hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"
   strings:
      $x1 = "%s\\%d.gho" fullword ascii
      $x2 = "%s\\nt%s.dll" fullword ascii
      $x3 = "baijinUPdate" fullword ascii

      $s1 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
      $s2 = "serviceone" fullword ascii
      $s3 = "#p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #f #" fullword ascii
      $s4 = "servicetwo" fullword ascii
      $s5 = "UpdateCrc" fullword ascii
      $s6 = "#[ #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #" fullword ascii
      $s7 = "nwsaPAgEnT" fullword ascii
      $s8 = "%-24s %-15s 0x%x(%d) " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of ($x*) or 4 of them )
}

rule Backdoor_Nitol_Jun17 {
   meta:
      description = "Detects malware backdoor Nitol - file wyawou.exe - Attention: this rule also matches on Upatre Downloader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/OOB3mH"
      date = "2017-06-04"
      hash1 = "cba19d228abf31ec8afab7330df3c9da60cd4dae376552b503aea6d7feff9946"
   strings:
      $x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $x3 = "TCPConnectFloodThread.target = %s" fullword ascii

      $s1 = "\\Program Files\\Internet Explorer\\iexplore.exe" fullword ascii
      $s2 = "%c%c%c%c%c%c.exe" fullword ascii
      $s3 = "GET %s%s HTTP/1.1" fullword ascii
      $s4 = "CCAttack.target = %s" fullword ascii
      $s5 = "Accept-Language: zh-cn" fullword ascii
      $s6 = "jdfwkey" fullword ascii
      $s7 = "hackqz.f3322.org:8880" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 5 of ($s*) ) ) or ( all of them )
}
