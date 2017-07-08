/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-07
   Identifier: HDRoot
   Reference: Winnti HDRoot VT
*/

/* Rule Set ----------------------------------------------------------------- */

rule HDRoot_Sample_Jul17_1 {
   meta:
      description = "Detects HDRoot samples"
      author = "Florian Roth"
      reference = "Winnti HDRoot VT"
      date = "2017-07-07"
      hash1 = "6d2ad82f455becc8c830d000633a370857928c584246a7f41fe722cc46c0d113"
   strings:
      $s1 = "gleupdate.dll" fullword ascii
      $s2 = "\\DosDevices\\%ws\\system32\\%ws" fullword wide
      $s3 = "l\\Driver\\nsiproxy" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and 3 of them )
}

rule HDRoot_Sample_Jul17_2 {
   meta:
      description = "Detects HDRoot samples"
      author = "Florian Roth"
      reference = "Winnti HDRoot VT"
      date = "2017-07-07"
      super_rule = 1
      hash1 = "1c302ed9786fc600073cc6f3ed2e50e7c23785c94a2908f74f92971d978b704b"
      hash2 = "3b7cfa40e26fb6b079b55ec030aba244a6429e263a3d9832e32ab09e7a3c4a9c"
      hash3 = "71eddf71a94c5fd04c9f3ff0ca1eb6b1770df1a3a8f29689fb8588427b5c9e8e"
      hash4 = "80e088f2fd2dbde0f9bc21e056b6521991929c4e0ecd3eb5833edff6362283f4"
   strings:
      $x1 = "http://microsoftcompanywork.htm" fullword ascii
      $x2 = "compose.aspx?s=%4X%4X%4X%4X%4X%4X" fullword ascii

      $t1 = "http://babelfish.yahoo.com/translate_url?" fullword ascii
      $t2 = "http://translate.google.com/translate?prev=hp&hl=en&js=n&u=%s?%d&sl=es&tl=en" fullword ascii

      $u1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.5." ascii
      $u2 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon)" fullword ascii
      $u3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon; TERA:" fullword ascii

      $s1 = "\\system32\\ntoskrnl.exe" fullword ascii
      $s2 = "Schedsvc.dll" fullword wide
      $s3 = "dllserver64.dll" fullword ascii
      $s4 = "C:\\TERA_SR.txt" fullword ascii
      $s5 = "updatevnsc.dat" fullword wide
      $s6 = "tera dll service global event" fullword ascii
      $s7 = "Referer: http://%s/%s" fullword ascii
      $s8 = "tera replace dll config" fullword ascii
      $s9 = "SetupDll64.dll" fullword ascii
      $s10 = "copy %%ComSpec%% \"%s\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) or all of ($u*) or 8 of them )
}

rule Unspecified_Malware_Jul17_1A {
   meta:
      description = "Detects samples of an unspecified malware - July 2017"
      author = "Florian Roth"
      reference = "Winnti HDRoot VT"
      date = "2017-07-07"
      hash1 = "e1c38142b6194237a4cd4603829aa6edb6436e7bba15e3e6b0c9e8c6b629b42b"
   strings:
      $s1 = "%SystemRoot%\\System32\\wuauserv.dll" fullword ascii
      $s2 = "systemroot%\\system32\\wuauserv.dll" fullword ascii
      $s3 = "ocgen.logIN" fullword wide
      $s4 = "ocmsn.logIN" fullword wide
      $s5 = "Install.log" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and all of them )
}