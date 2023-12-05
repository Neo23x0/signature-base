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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "e12031da58c0b08e8b610c3786ca2b66fcfea8ddc9ac558d08a29fd27e95a3e7"
      id = "21e858b1-2cfa-5757-96f0-7c44a5da6898"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "1aef507c385a234e8b10db12852ad1bd66a04730451547b2dcb26f7fae16e01f"
      id = "5858541b-c394-5be8-9db3-fcff66f635de"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "2f98ac11c78ad1b4c5c5c10a88857baf7af43acb9162e8077709db9d563bcf02"
      id = "bff79813-0d72-50d9-9676-794801edc34b"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "15ededb19ec5ab6f03db1106d2ccdeeacacdb8cd708518d065cacb1b0d7e955d"
      id = "4e926b1c-bf10-5337-8c3a-964008a37d8b"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "a8b7e3edaa18c6127e98741503c3a2a66b7720d2abd967c94b8a5f2e99575ac5"
      id = "4bd60f61-a595-5289-9595-a7e33f265748"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/8abDE6"
      date = "2016-12-14"
      hash1 = "dbd8cbbaf59d19cf7566042945e36409cd090bc711e339d3f2ec652bc26d6a03"
      id = "0f36eb56-39d8-536c-93ff-4a2352163612"
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
