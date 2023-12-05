/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-10-20
   Identifier: PassCV Group (Cylance)
*/

/* Rule Set ----------------------------------------------------------------- */

rule PassCV_Sabre_Malware_1 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "24a9bfbff81615a42e42755711c8d04f359f3bf815fb338022edca860ff1908a"
      hash2 = "e61e56b8f2666b9e605127b4fcc7dc23871c1ae25aa0a4ea23b48c9de35d5f55"
      id = "99a26daa-c563-5b23-89b9-965d8ce7229d"
   strings:
      $x1 = "F:\\Excalibur\\Excalibur\\Excalibur\\" ascii
      $x2 = "bin\\oSaberSvc.pdb" ascii

      $s1 = "cmd.exe /c MD " fullword ascii
      $s2 = "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=0&rsv_idx=1&tn=baidu&wd=ip138" fullword wide
      $s3 = "CloudRun.exe" fullword wide
      $s4 = "SaberSvcB.exe" fullword wide
      $s5 = "SaberSvc.exe" fullword wide
      $s6 = "SaberSvcW.exe" fullword wide
      $s7 = "tianshiyed@iaomaomark1#23mark123tokenmarkqwebjiuga664115" fullword wide
      $s8 = "Internet Connect Failed!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) and 5 of ($s*) ) ) or ( all of them )
}

rule PassCV_Sabre_Malware_Signing_Cert {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      score = 50
      hash1 = "7c32885c258a6d5be37ebe83643f00165da3ebf963471503909781540204752e"
      id = "2b2d1313-6454-5e3f-9b58-5b1a26739ba8"
   strings:
      $s1 = "WOODTALE TECHNOLOGY INC" ascii
      $s2 = "Flyingbird Technology Limited" ascii
      $s3 = "Neoact Co., Ltd." ascii
      $s4 = "AmazGame Age Internet Technology Co., Ltd" ascii
      $s5 = "EMG Technology Limited" ascii
      $s6 = "Zemi Interactive Co., Ltd" ascii
      $s7 = "337 Technology Limited" ascii
      $s8 = "Runewaker Entertainment0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them )
}

rule PassCV_Sabre_Malware_2 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "475d1c2d36b2cf28b28b202ada78168e7482a98b42ff980bbb2f65c6483db5b4"
      hash2 = "009645c628e719fad2e280ef60bbd8e49bf057196ac09b3f70065f1ad2df9b78"
      hash3 = "92479c7503393fc4b8dd7c5cd1d3479a182abca3cda21943279c68a8eef9c64b"
      hash4 = "0c7b952c64db7add5b8b50b1199fc7d82e9b6ac07193d9ec30e5b8d353b1f6d2"
      id = "dd9eb5f6-9faa-584d-b3b5-6dcfdc3f359c"
   strings:
      $x1 = "ncProxyXll" fullword ascii

      $s1 = "Uniscribe.dll" fullword ascii
      $s2 = "WS2_32.dll" ascii
      $s3 = "ProxyDll" fullword ascii
      $s4 = "JDNSAPI.dll" fullword ascii
      $s5 = "x64.dat" fullword ascii
      $s6 = "LSpyb2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and $x1 ) or ( all of them )
}

rule PassCV_Sabre_Malware_Excalibur_1 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "21566f5ff7d46cc9256dae8bc7e4c57f2b9261f95f6ad2ac921558582ea50dfb"
      hash2 = "02922c5d994e81629d650be2a00507ec5ca221a501fe3827b5ed03b4d9f4fb70"

      id = "eadad36c-49c8-50e1-8334-813d2e760fe9"
   strings:
      $x1 = "F:\\Excalibur\\Excalibur\\" ascii
      $x2 = "Excalibur\\bin\\Shell.pdb" ascii
      $x3 = "SaberSvc.exe" wide

      $s1 = "BBB.exe" fullword wide
      $s2 = "AAA.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of ($x*) or all of ($s*) )
      or 3 of them
}

rule PassCV_Sabre_Malware_3 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "28c7575b2368a9b58d0d1bf22257c4811bd3c212bd606afc7e65904041c29ce1"
      id = "03e5efc0-6076-501f-a600-b3d9008a8711"
   strings:
      $x1 = "NXKILL" fullword wide

      $s1 = "2OLE32.DLL" fullword ascii
      $s2 = "localspn.dll" fullword wide
      $s3 = "!This is a Win32 program." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 8000KB and $x1 and 2 of ($s*) )
}

rule PassCV_Sabre_Malware_4 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "27463bcb4301f0fdd95bc10bf67f9049e161a4e51425dac87949387c54c9167f"
      id = "f182064d-3a91-5a61-aa0f-2ce491a60126"
   strings:
      $s1 = "QWNjZXB0On" fullword ascii /* base64 encoded string 'Accept:' */
      $s2 = "VXNlci1BZ2VudDogT" fullword ascii /* b64: User-Agent: */
      $s3 = "dGFzay5kbnME3luLmN" fullword ascii /* b64: task.dns[ */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule PassCV_Sabre_Tool_NTScan {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "0f290612b26349a551a148304a0bd3b0d0651e9563425d7c362f30bd492d8665"
      id = "6ec3371a-2a1c-53d1-b650-d28728db1b40"
   strings:
      $x1 = "NTscan.EXE" fullword wide
      $x2 = "NTscan Microsoft " fullword wide

      $s1 = "admin$" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}

rule PassCV_Sabre_Malware_5 {
   meta:
      description = "PassCV Malware mentioned in Cylance Report"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/digitally-signed-malware-targeting-gaming-companies"
      date = "2016-10-20"
      hash1 = "03aafc5f468a84f7dd7d7d38f91ff17ef1ca044e5f5e8bbdfe589f5509b46ae5"
      id = "ce8d1b9e-7750-5796-a048-20bfd48c6aee"
   strings:
      $x1 = "ncircTMPg" fullword ascii
      $x2 = "~SHELL#" fullword ascii
      $x3 = "N.adobe.xm" fullword ascii

      $s1 = "NEL32.DLL" fullword ascii
      $s2 = "BitLocker.exe" fullword wide
      $s3 = "|xtplhd" fullword ascii /* reversed goodware string 'dhlptx|' */
      $s4 = "SERVICECORE" fullword wide
      $s5 = "SHARECONTROL" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and 1 of ($x*) or all of ($s*) )
}
