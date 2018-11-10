
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-28
   Identifier: Suckfly
   Reference: https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Suckfly_Nidiran_Gen_1 {
   meta:
      description = "Detects Suckfly Nidiran Trojan"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
      date = "2018-01-28"
      hash1 = "ac7d7c676f58ebfa5def9b84553f00f283c61e4a310459178ea9e7164004e734"
   strings:
      $s1 = "WriteProcessMemory fail at %d " fullword ascii
      $s2 = "CreateRemoteThread fail at %d " fullword ascii
      $s3 = "CreateRemoteThread Succ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule Suckfly_Nidiran_Gen_2 {
   meta:
      description = "Detects Suckfly Nidiran Trojan"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
      date = "2018-01-28"
      hash1 = "b53a316a03b46758cb128e5045dab2717cb36e7b5eb1863ce2524d4f69bc2cab"
      hash2 = "eaee2bf83cf90d35dab8a4711f7a5f2ebf9741007668f3746995f4564046fbdf"
   strings:
      $x1 = "WorkDll.dll" fullword ascii
      $x2 = "%userprofile%\\Security Center\\secriter.dll" fullword ascii

      $s1 = "DLL_PROCESS_ATTACH is called" fullword ascii
      $s2 = "Support Security Accounts Manager For Microsoft Windows.If this service is stopped, any services that depended on it will fail t" ascii
      $s3 = "before CreateRemoteThread" fullword ascii
      $s4 = "CreateRemoteThread Succ" fullword ascii
      $s5 = "Microsoft Security Accounts Manager" fullword ascii
      $s6 = "DoRunRemote" fullword ascii
      $s7 = "AutoRunFun" fullword ascii
      $s8 = "ServiceMain is called" fullword ascii
      $s9 = "DllRegisterServer is called" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
        1 of ($x*) or
        4 of them
      )
}

rule Suckfly_Nidiran_Gen_3 {
   meta:
      description = "Detects Suckfly Nidiran Trojan"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.symantec.com/connect/blogs/suckfly-revealing-secret-life-your-code-signing-certificates"
      date = "2018-01-28"
      hash1 = "c2022e1114b162e79e44d974fd310d53e1bbdd8cb4f217553c1227cafed78855"
      hash2 = "47731c9d985ebc2bd7227fced3cc44c6d72e29b52f76fccbdaddd76cc3450706"
   strings:
      $x1 = "RUN SHELLCODE FAIL" fullword ascii
      $x2 = "RUN PROCESS FAILD!" fullword ascii
      $x3 = "DOWNLOAD FILE FAILD" fullword ascii
      $x4 = "MODIFYCONFIG FAIL!" fullword ascii
      $x5 = "GetFileAttributes FILE FAILD" fullword ascii
      $x6 = "MODIFYCONFIG SUCC!" fullword ascii

      $s1 = "cmd.exe /c %s" fullword ascii
      $s2 = "error to create pipe!" fullword ascii
      $s3 = "%s\\%08x.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
        pe.imphash() == "ae0f4ebf7e8ce91d6548318a3cf82b7a" or
        1 of ($x*) or
        2 of them
      )
}