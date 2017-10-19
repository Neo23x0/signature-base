/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: OilRig
   Reference: https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/
*/

/* Rule Set ----------------------------------------------------------------- */

rule OilRig_Strings_Oct17 {
   meta:
      description = "Detects strings from OilRig malware and malicious scripts"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/"
      date = "2017-10-18"
   strings:
      $x1 = "%localappdata%\\srvHealth.exe" fullword wide ascii
      $x2 = "%localappdata%\\srvBS.txt" fullword wide ascii
      $x3 = "Agent Injector\\PolicyConverter\\Inner\\obj\\Release\\Inner.pdb" fullword ascii
      $x4 = "Agent Injector\\PolicyConverter\\Joiner\\obj\\Release\\Joiner.pdb" fullword ascii
      $s3 = ".LoadDll(\"Run\", arg, \"C:\\\\Windows\\\\" ascii
   condition:
      filesize < 800KB and 1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: OilRig
   Reference: https://goo.gl/JQVfFP
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule OilRig_ISMAgent_Campaign_Samples1 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18"
      hash1 = "119c64a8b35bd626b3ea5f630d533b2e0e7852a4c59694125ff08f9965b5f9cc"
      hash2 = "0ccb2117c34e3045a4d2c0d193f1963c8c0e8566617ed0a561546c932d1a5c0c"
   strings:
      $s1 = "###$$$TVqQAAMAAAAEAAAA" ascii
      $s2 = "C:\\Users\\J-Win-7-32-Vm\\Desktop\\error.jpg" fullword wide
      $s3 = "$DATA = [System.Convert]::FromBase64String([IO.File]::ReadAllText('%Base%'));[io.file]::WriteAllBytes(" ascii
      $s4 = " /c echo powershell > " fullword wide ascii
      $s5 = "\\Libraries\\servicereset.exe" fullword wide
      $s6 = "%DestFolder%" fullword wide ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and 2 of them
}

rule OilRig_ISMAgent_Campaign_Samples2 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18"
      hash1 = "fcad263d0fe2b418db05f47d4036f0b42aaf201c9b91281dfdcb3201b298e4f4"
      hash2 = "33c187cfd9e3b68c3089c27ac64a519ccc951ccb3c74d75179c520f54f11f647"
   strings:
      $x1 = "PolicyConverter.exe" fullword wide
      $x2 = "SrvHealth.exe" fullword wide
      $x3 = "srvBS.txt" fullword wide

      $s1 = "{a3538ba3-5cf7-43f0-bc0e-9b53a98e1643}, PublicKeyToken=3e56350693f7355e" fullword wide
      $s2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and ( 2 of ($x*) or 3 of them )
}

rule OilRig_ISMAgent_Campaign_Samples3 {
   meta:
      description = "Detects OilRig malware from Unit 42 report in October 2017"
      author = "Florian Roth"
      reference = "https://goo.gl/JQVfFP"
      date = "2017-10-18"
      hash1 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
   strings:
      $x1 = "cmd /c schtasks /query /tn TimeUpdate > NUL 2>&1" ascii
      $x2 = "schtasks /create /sc minute /mo 0002 /tn TimeUpdate /tr" fullword ascii
      $x3 = "-c  SampleDomain.com -m scheduleminutes" fullword ascii
      $x4 = ".ntpupdateserver.com" fullword ascii
      $x5 = ".msoffice365update.com" fullword ascii

      $s1 = "out.exe" fullword ascii
      $s2 = "\\Win32Project1\\Release\\Win32Project1.pdb" ascii
      $s3 = "C:\\windows\\system32\\cmd.exe /c (" fullword ascii
      $s4 = "Content-Disposition: form-data; name=\"file\"; filename=\"a.a\"" fullword ascii
      $s5 = "Agent configured successfully" fullword ascii
      $s6 = "\\runlog*" fullword ascii
      $s7 = "can not specify username!!" fullword ascii
      $s8 = "Agent can not be configured" fullword ascii
      $s9 = "%08lX%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" fullword ascii
      $s10 = "!!! can not create output file !!!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "538805ecd776b9a42e71aebf94fde1b1" or
         pe.imphash() == "861ac226fbe8c99a2c43ff451e95da97" or
         ( 1 of ($x*) or 3 of them )
      )
}