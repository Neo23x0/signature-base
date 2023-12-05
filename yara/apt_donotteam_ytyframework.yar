import "pe"

rule APT_DonotTeam_YTYframework : APT DonotTeam Windows {
   meta:
      author = "James E.C, ProofPoint"
      description = "Modular malware framework with similarities to EHDevel"
      hashes = "1e0c1b97925e1ed90562d2c68971e038d8506b354dd6c1d2bcc252d2a48bc31c"
      reference = "https://www.arbornetworks.com/blog/asert/donot-team-leverages-new-modular-malware-framework-south-asia/"
      reference2 = "https://labs.bitdefender.com/2017/09/ehdevel-the-story-of-a-continuously-improving-advanced-threat-creation-toolkit/"
      date = "08-03-2018"
      id = "6dd07019-aa5a-5966-8331-b6f6758b0652"
   strings:
      $x1 = "/football/download2/" ascii wide
      $x2 = "/football/download/" ascii wide
      $x3 = "Caption: Xp>" wide

      $x_c2 = "5.135.199.0" ascii fullword

      $a1 = "getGoogle" ascii fullword
      $a2 = "/q /noretstart" wide
      $a3 = "IsInSandbox" ascii fullword
      $a4 = "syssystemnew" ascii fullword
      $a5 = "ytyinfo" ascii fullword
      $a6 = "\\ytyboth\\yty " ascii

      $s1 = "SELECT Name FROM Win32_Processor" wide
      $s2 = "SELECT Caption FROM Win32_OperatingSystem" wide
      $s3 = "SELECT SerialNumber FROM Win32_DiskDrive" wide
      $s4 = "VM: Yes" wide fullword
      $s5 = "VM: No" wide fullword
      $s6 = "helpdll.dll" ascii fullword
      $s7 = "boothelp.exe" ascii fullword
      $s8 = "SbieDll.dll" wide fullword
      $s9 = "dbghelp.dll" wide fullword
      $s10 = "YesNoMaybe" ascii fullword
      $s11 = "saveData" ascii fullword
      $s12 = "saveLogs" ascii fullword
   condition:
      uint16be(0) == 0x4d5a and filesize < 500KB and (
         pe.imphash() == "87775285899fa860b9963b11596a2ded" or
         1 of ($x*) or 3 of ($a*) or 6 of ($s*)
      )
}
