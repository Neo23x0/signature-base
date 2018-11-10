/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-25
   Identifier: Greenbug Malware
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Greenbug_Malware_1 {
   meta:
      description = "Detects Malware from Greenbug Incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
   strings:
      $s1 = "vailablez" fullword ascii
      $s2 = "Sfouglr" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and all of them )
}

rule Greenbug_Malware_2 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      hash1 = "6b28a43eda5b6f828a65574e3f08a6d00e0acf84cbb94aac5cec5cd448a4649d"
      hash2 = "21f5e60e9df6642dbbceca623ad59ad1778ea506b7932d75ea8db02230ce3685"
      hash3 = "319a001d09ee9d754e8789116bbb21a3c624c999dae9cf83fde90a3fbe67ee6c"
   strings:
      $x1 = "|||Command executed successfully" fullword ascii
      $x2 = "\\Release\\Bot Fresh.pdb" ascii
      $x3 = "C:\\ddd\\a1.txt" fullword wide
      $x4 = "Bots\\Bot5\\x64\\Release" ascii
      $x5 = "Bot5\\Release\\Ism.pdb" ascii
      $x6 = "Bot\\Release\\Ism.pdb" ascii
      $x7 = "\\Bot Fresh\\Release\\Bot" ascii

      $s1 = "/Home/SaveFile?commandId=CmdResult=" fullword wide
      $s2 = "raB3G:Sun:Sunday:Mon:Monday:Tue:Tuesday:Wed:Wednesday:Thu:Thursday:Fri:Friday:Sat:Saturday" fullword ascii
      $s3 = "Set-Cookie:\\b*{.+?}\\n" fullword wide
      $s4 = "SELECT * FROM AntiVirusProduct" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 2 of them ) ) or ( 3 of them )
}

rule Greenbug_Malware_3 {
   meta:
      description = "Detects Backdoor from Greenbug Incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash2 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
   strings:
      $x1 = "F:\\Projects\\Bot\\Bot\\Release\\Ism.pdb" fullword ascii
      $x2 = "C:\\ddd\\wer2.txt" fullword wide
      $x3 = "\\Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition:
      1 of them
}

rule Greenbug_Malware_4 {
   meta:
      description = "Detects ISMDoor Backdoor"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
   strings:
      $s1 = "powershell.exe -nologo -windowstyle hidden -c \"Set-ExecutionPolicy -scope currentuser" fullword ascii
      $s2 = "powershell.exe -c \"Set-ExecutionPolicy -scope currentuser -ExecutionPolicy unrestricted -f; . \"" fullword ascii
      $s3 = "c:\\windows\\temp\\tmp8873" fullword ascii
      $s4 = "taskkill /im winit.exe /f" fullword ascii
      $s5 = "invoke-psuacme"
      $s6 = "-method oobe -payload \"\"" fullword ascii
      $s7 = "C:\\ProgramData\\stat2.dat" fullword wide
      $s8 = "Invoke-bypassuac" fullword ascii
      $s9 = "Start Keylog Done" fullword wide
      $s10 = "Microsoft\\Windows\\WinIt.exe" fullword ascii
      $s11 = "Microsoft\\Windows\\Tmp9932u1.bat\"" fullword ascii
      $s12 = "Microsoft\\Windows\\tmp43hh11.txt" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them ) or ( 3 of them )
}

rule Greenbug_Malware_5 {
   meta:
      description = "Auto-generated rule"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/urp4CD"
      date = "2017-01-25"
      super_rule = 1
      hash1 = "308a646f57c8be78e6a63ffea551a84b0ae877b23f28a660920c9ba82d57748f"
      hash2 = "44bdf5266b45185b6824898664fd0c0f2039cdcb48b390f150e71345cd867c49"
      hash3 = "7f16824e7ad9ee1ad2debca2a22413cde08f02ee9f0d08d64eb4cb318538be9c"
      hash4 = "82beaef407f15f3c5b2013cb25901c9fab27b086cadd35149794a25dce8abcb9"
   strings:
      $x1 = "cmd /u /c WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter" fullword ascii
      $x2 = "cmd /a /c net user administrator /domain >>" fullword ascii
      $x3 = "cmd /a /c netstat -ant >>\"%localappdata%\\Microsoft\\" fullword ascii

      $o1 = "========================== (Net User) ==========================" ascii fullword
   condition:
      filesize < 2000KB and (
         ( uint16(0) == 0x5a4d and 1 of them ) or
         $o1
      )
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-26
   Identifier: Greenbug
   Reference: http://www.clearskysec.com/greenbug/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Greenbug_Malware_Nov17_1 {
   meta:
      description = "Detects Greenbug Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://www.clearskysec.com/greenbug/"
      date = "2017-11-26"
      hash1 = "6e55e161dc9ace3076640a36ef4a8819bb85c6d5e88d8e852088478f79cf3b7c"
      hash2 = "a9f1375da973b229eb649dc3c07484ae7513032b79665efe78c0e55a6e716821"
   strings:
      $x1 = "AgentV2.exe  -c  SampleDomain.com" fullword ascii
      $x2 = ".ntpupdateserver.com" fullword ascii
      $x3 = "Content-Disposition: form-data; name=\"file\"; filename=\"a.a\"" fullword ascii
      $x4 = "a67d0db885a3432576548a2a03707334" fullword ascii
      $x5 = "a67d0db8a2a173347654432503702aa3" fullword ascii
      $x6 = "!!! can not create output file !!!" fullword ascii

      $s1 = "\\runlog*" fullword ascii
      $s2 = "can not specify username!!" fullword ascii
      $s3 = "Agent can not be configured" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
        pe.imphash() == "58ba44f7ff5436a603fec3df97d815ea" or
        pe.imphash() == "538805ecd776b9a42e71aebf94fde1b1" or
        1 of ($x*) or
        3 of them
      )
}
