/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-06-21
   Identifier: Thrip APT
   Reference: https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_Thrip_Sample_Jun18_1 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "59509a17d516813350fe1683ca6b9727bd96dd81ce3435484a5a53b472ff4ae9"
   strings:
      $s1 = "idocback.dll" fullword ascii
      $s2 = "constructor or from DllMain." fullword ascii
      $s3 = "appmgmt" fullword ascii
      $s4 = "chksrv" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule APT_Thrip_Sample_Jun18_2 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "1fc9f7065856cd8dc99b6f46cf0953adf90e2c42a3b65374bf7b50274fb200cc"
   strings:
      $s1 = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" fullword ascii
      $s2 = "ProbeScriptFint" fullword wide
      $s3 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule APT_Thrip_Sample_Jun18_3 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "0d2abdcaad99e102fdf6574b3dc90f17cb9d060c20e6ac4ff378875d3b91a840"
   strings:
      $s1 = "C:\\Windows\\SysNative\\cmd.exe" fullword ascii
      $s2 = "C:\\Windows\\SysNative\\sysprep\\cryptbase.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule APT_Thrip_Sample_Jun18_4 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "6b236d3fc54d36e6dc2a26299f6ded597058fed7c9099f1a37716c5e4b162abc"
   strings:
      $s1 = "\\system32\\wbem\\tmf\\caches_version.db" fullword ascii
      $s2 = "ProcessName No Access" fullword ascii
      $s3 = "Hwnd of Process NULL" fullword ascii
      $s4 = "*********The new session is be opening:(%d)**********" fullword ascii
      $s5 = "[EXECUTE]" fullword ascii
      $s6 = "/------------------------------------------------------------------------" fullword ascii
      $s7 = "constructor or from DllMain." fullword ascii
      $s8 = "Time:%d-%d-%d %d:%d:%d" fullword ascii
      $s9 = "\\info.config" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 5 of them
}

rule APT_Thrip_Sample_Jun18_5 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "32889639a27961497d53176765b3addf9fff27f1c8cc41634a365085d6d55920"
   strings:
      $s2 = "c:\\windows\\USBEvent.exe" fullword ascii
      $s5 = "c:\\windows\\spdir.dat" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule APT_Thrip_Sample_Jun18_6 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "44f58496578e55623713c4290abb256d03103e78e99939daeec059776bd79ee2"
   strings:
      $s1 = "C:\\Windows\\system32\\Instell.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule APT_Thrip_Sample_Jun18_7 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "6b714dc1c7e58589374200d2c7f3d820798473faeb26855e53101b8f3c701e3f"
   strings:
      $s1 = "C:\\runme.exe" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and 1 of them
}

rule APT_Thrip_Sample_Jun18_8 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "0f2d09b1ad0694f9e71eeebec5b2d137665375bf1e76cb4ae4d7f20487394ed3"
   strings:
      $x1 = "$.oS.Run('cmd.exe /c '+a+'" fullword ascii
      $x2 = "new $._x('WScript.Shell');" ascii
      $x3 = ".ExpandEnvironmentStrings('%Temp%')+unescape('" ascii
   condition:
      filesize < 10KB and 1 of ($x*)
}

rule APT_Thrip_Sample_Jun18_9 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "8e6682bcc51643f02a864b042f7223b157823f3d890fe21d38caeb43500d923e"
      hash2 = "0c8ca0fd0ec246ef207b96a3aac5e94c9c368504905b0a033f11eef8c62fa14c"
      hash3 = "6d0a2c822e2bc37cc0cec35f040d3fec5090ef2775df658d3823e47a93a5fef3"
      hash4 = "0c49d1632eb407b5fd0ce32ed45b1c783ac2ef60d001853ae1f6b7574e08cfa9"
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         pe.imphash() == "a7f0714e82b3105031fa7bc89dfe7664" or
         pe.imphash() == "8812ff21aeb160e8800257140acae54b" or
         pe.imphash() == "44a1e904763fe2d0837c747c7061b010" or
         pe.imphash() == "51a854d285aa12eb82e76e6e1be01573" or
         pe.imphash() == "a1f457c8c549c5c430556bfe5887a4e6"
      )
}

rule APT_Thrip_Sample_Jun18_10 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "350d2a6f8e6a4969ffbf75d9f9aae99e7b3a8cd8708fd66f977e07d7fbf842e3"
   strings:
      $x1 = "!This Program cannot be run in DOS mode." fullword ascii
      $x2 = "!this program cannot be run in dos mode." fullword ascii

      $s1 = "svchost.dll" fullword ascii
      $s2 = "constructor or from DllMain." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and ( $x1 or 2 of them )
}

rule APT_Thrip_Sample_Jun18_11 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "590a6796b97469f8e6977832a63c0964464901f075a9651f7f1b4578e55bd8c8"
   strings:
      $s1 = "\\AppData\\Local\\Temp\\dw20.EXE" ascii
      $s2 = "C:\\Windows\\system32\\sysprep\\cryptbase.dll" fullword ascii
      $s3 = "WFQNJMBWF" fullword ascii
      $s4 = "SQLWLWZSF" fullword ascii
      $s5 = "PFQUFQSBPP" fullword ascii
      $s6 = "WQZXQFPVOW" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB
      and ( pe.imphash() == "6eef4394490378f32d134ab3bf4bf194" or all of them )
}

rule APT_Thrip_Sample_Jun18_12 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "33c01d3266fe6a70e8785efaf10208f869ae58a17fd9cdb2c6995324c9a01062"
   strings:
      $s1 = "pGlobal->nOSType==64--%s\\cmd.exe %s" fullword ascii
      $s2 = "httpcom.log" fullword ascii
      $s3 = "\\CryptBase.dll" fullword ascii
      $s4 = "gupdate.exe" fullword ascii
      $s5 = "wusa.exe" fullword ascii
      $s6 = "/c %s %s /quiet /extract:%s\\%s\\" fullword ascii
      $s7 = "%s%s.dll.cab" fullword ascii
      $s8 = "/c %s\\%s\\%s%s %s" fullword ascii
      $s9 = "ReleaseEvildll" fullword ascii
      $s0 = "%s\\%s\\%s%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 6 of them
}

rule APT_Thrip_Sample_Jun18_13 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "780620521c92aab3d592b3dc149cbf58751ea285cfdaa50510002b441796b312"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" fullword ascii
      $s2 = "<member><name>password</name>" fullword ascii
      $s3 = "<value><string>qqtorspy</string></value>" fullword ascii
      $s4 = "SOFTWARE\\QKitTORSPY" fullword wide
      $s5 = "ipecho.net" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB
      and ( pe.imphash() == "3dfad33b2fb66c083c99dc10341908b7" or 4 of them )
}

rule APT_Thrip_Sample_Jun18_14 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "67dd44a8fbf6de94c4589cf08aa5757b785b26e49e29488e9748189e13d90fb3"
   strings:
      $s1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
      $s2 = "spdirs.dll" fullword ascii
      $s3 = "Provides storm installation services such as Publish, and Remove." fullword ascii
      $s4 = "RegSetValueEx(Svchost\\netsvcs)" fullword ascii
      $s5 = "Load %s Error" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         ( pe.exports("InstallA") and pe.exports("InstallB") and pe.exports("InstallC") ) or
         all of them
      )
}

rule APT_Thrip_Sample_Jun18_15 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "231c569f11460a12b171f131c40a6f25d8416954b35c28ae184aba8a649d9786"
   strings:
      $s1 = "%s\\cmd.exe /c %s" fullword ascii
      $s2 = "CryptBase.dll" fullword ascii
      $s3 = "gupdate.exe" fullword ascii
      $s4 = "wusa.exe" fullword ascii
      $s5 = "/c %s %s /quiet /extract:%s\\%s\\" fullword ascii
      $s6 = "%s%s.dll.cab" fullword ascii
      $s7 = "%s\\%s\\%s%s %s" fullword ascii
      $s8 = "%s\\%s\\%s%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB
      and ( pe.imphash() == "f6ec70a295000ab0a753aa708e9439b4" or 6 of them )
}

rule APT_Thrip_Sample_Jun18_16 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "2b1c1c6d82837dbbccd171a0413c1d761b1f7c3668a21c63ca06143e731f030e"
   strings:
      $s1 = "[%d] Failed, %08X" fullword ascii
      $s2 = "woqunimalegebi" fullword ascii
      $s3 = "[%d] Offset can not fetched." fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB
      and ( all of them or pe.imphash() == "c6a4c95d868a3327a62c9c45f5e15bbf" )
}

rule APT_Thrip_Sample_Jun18_17 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "05036de73c695f59adf818d3c669c48ce8626139d463b8a7e869d8155e5c0d85"
      hash2 = "08d8c610e1ec4a02364cb53ba44e3ca5d46e8a177a0ecd50a1ef7b5db252701d"
      hash3 = "14535607d9a7853f13e8bf63b629e3a19246ed9db6b4d2de2ca85ec7a7bee140"
   strings:
      $x1 = "c:\\users\\administrator\\desktop\\code\\skeyman2\\" ascii
      $x2 = "\\SkeyMan2.pdb" ascii
      $x3 = "\\\\.\\Pnpkb" fullword ascii

      $s1 = "\\DosDevices\\Pnpkb" fullword wide
      $s2 = "\\DosDevices\\PnpKb" fullword wide
      $s3 = "\\Driver\\kbdhid" fullword wide
      $s4 = "\\Device\\PnpKb" fullword wide
      $s5 = "Microsoft  Windows Operating System" fullword wide
      $s6 = "hDevice == INVALID_HANDLE_VALUE" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) and 1 of ($s*) )
}

rule APT_Thrip_Sample_Jun18_18 {
   meta:
      description = "Detects sample found in Thrip report by Symantec "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
      date = "2018-06-21"
      hash1 = "33029f5364209e05481cfb2a4172c6dc157b0070f51c05dd34485b8e8da6e820"
      hash2 = "263c01a3b822722dc288a5ac138d953630d8c548a0bee080ae3979b7d364cecb"
      hash3 = "52d190a8d20b4845551b8765cbd12cfbe04cf23e6812e238e5a5023c34ee9b37"
      hash4 = "1f019e3c30a02b7b65f7984903af11d561d02b2666cc16463c274a2a0e62145d"
      hash5 = "43904ea071d4dce62a21c69b8d6efb47bcb24c467c6f6b3a6a6ed6cd2158bfe5"
      hash6 = "00d9da2b665070d674acdbb7c8f25a01086b7ca39d482d55f08717f7383ee26a"
   strings:
      $s1 = "Windows 95/98/Me, Windows NT 4.0, Windows 2000/XP: IME PROCESS key" fullword ascii
      $s2 = "Windows 2000/XP: Either the angle bracket key or the backslash key on the RT 102-key keyboard" fullword ascii
      $s3 = "LoadLibraryA() failed in KbdGetProcAddressByName()" fullword ascii
      $s5 = "Unknown Virtual-Key Code" fullword ascii
      $s6 = "Computer Sleep key" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them
}
