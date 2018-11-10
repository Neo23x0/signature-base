/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-14
   Identifier: PROMETHIUM and NEODYMIUM
*/

/* Rule Set ----------------------------------------------------------------- */

rule PROMETHIUM_NEODYMIUM_Malware_1 {
   meta:
      description = "Detects PROMETHIUM and NEODYMIUM malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "e12031da58c0b08e8b610c3786ca2b66fcfea8ddc9ac558d08a29fd27e95a3e7"
   strings:
      $s1 = "c:\\Windows\\system32\\syswindxr32.dll" fullword wide
      $s2 = "c:\\windows\\temp\\TrueCrypt-Setup-7.1a-tamindir.exe" fullword wide
      $s3 = "%s\\ssleay32.dll" fullword wide
      $s4 = "%s\\libeay32.dll" fullword wide
      $s5 = "%s\\fprot32.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 10000KB and 3 of them ) or ( all of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_2 {
   meta:
      description = "Detects PROMETHIUM and NEODYMIUM malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "1aef507c385a234e8b10db12852ad1bd66a04730451547b2dcb26f7fae16e01f"
   strings:
      $s1 = "winasys32.exe" fullword ascii
      $s2 = "alg32.exe" fullword ascii
      $s3 = "wmsrv32.exe" fullword ascii
      $s4 = "vmnat32.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them ) or ( 3 of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_3 {
   meta:
      description = "Detects PROMETHIUM and NEODYMIUM malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "2f98ac11c78ad1b4c5c5c10a88857baf7af43acb9162e8077709db9d563bcf02"
   strings:
      $s1 = "%s SslHandshakeDone(%d) %d. Secure connection with %s, cipher %s, %d secret bits (%d total), session reused=%s" fullword ascii
      $s2 = "mvhost32.dll" fullword ascii
      $s3 = "sdwin32.dll" fullword ascii
      $s4 = "ofx64.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 2 of them ) or ( all of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_4 {
   meta:
      description = "Detects PROMETHIUM and NEODYMIUM malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "15ededb19ec5ab6f03db1106d2ccdeeacacdb8cd708518d065cacb1b0d7e955d"
   strings:
      $s1 = "c:\\windows\\temp\\winrar.exe" fullword wide
      $s2 = "info@aadobetech.com" fullword ascii
      $s3 = "%s\\ssleay32.dll" fullword wide
      $s4 = "%s\\libeay32.dll" fullword wide
      $s5 = "%s\\fprot32.exe" fullword wide
      $s6 = "ADOBE Corp.1" fullword ascii
      $s7 = "Adobe Flash Player1\"0 " fullword ascii
      $s8 = "Windows Index Services" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 4 of them ) or ( 6 of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_5 {
   meta:
      description = "Detects PROMETHIUM and NEODYMIUM malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "a8b7e3edaa18c6127e98741503c3a2a66b7720d2abd967c94b8a5f2e99575ac5"
   strings:
      $s1 = "Winxsys.exe" fullword wide
      $s2 = "%s\\ssleay32.dll" fullword wide
      $s3 = "%s\\libeay32.dll" fullword wide
      $s4 = "Windows Index Services" fullword wide
      $s5 = "<F RAT" fullword ascii
      $s6 = "WININDX-088FA840-B10D-11D3-BC36-006067709674" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and 3 of them )
}

rule PROMETHIUM_NEODYMIUM_Malware_6 {
   meta:
      description = "Detects PROMETHIUM and NEODYMIUM malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "dbd8cbbaf59d19cf7566042945e36409cd090bc711e339d3f2ec652bc26d6a03"
   strings:
      $s1 = "c:\\Windows\\system32\\syswindxr32.dll" fullword wide
      $s2 = "c:\\windows\\temp\\TrueCrypt-7.2.exe" fullword wide
      $s3 = "%s\\ssleay32.dll" fullword wide
      $s4 = "%s\\libeay32.dll" fullword wide
      $s5 = "%s\\fprot32.exe" fullword wide
      $s6 = "Windows Index Services" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 7000KB and 4 of them )
}
