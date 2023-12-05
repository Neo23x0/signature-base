
rule SUSP_XORed_Mozilla {
   meta:
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth"
      reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
      date = "2019-10-28"
      modified = "2023-11-25"
      score = 65
      id = "af7fc551-0d4e-589e-9152-95d9c4ab03bf"
   strings:
      $xo1 = "Mozilla/5.0" xor(0x01-0xff) ascii wide

      $fp1 = "Sentinel Labs" wide
      $fp2 = "<filter object at" ascii /* Norton Security */
   condition:
      $xo1
      and not 1 of ($fp*)
      and not uint32(0) == 0x434d5953 // Symantec AV sigs file
}

rule SUSP_XORed_MSDOS_Stub_Message {
   meta:
      description = "Detects suspicious XORed MSDOS stub message"
      author = "Florian Roth"
      reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
      date = "2019-10-28"
      modified = "2023-10-11"
      score = 55
      id = "9ab52434-9162-5fd5-bf34-8b163f6aeec4"
   strings:
      $xo1 = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
      $xo2 = "This program must be run under Win32" xor(0x01-0xff) ascii wide

      $fp1 = "AVAST Software" fullword wide ascii
      $fp2 = "AVG Netherlands" fullword wide ascii
      $fp3 = "AVG Technologies" ascii wide
      $fp4 = "Malicious Software Removal Tool" wide
      $fp5 = "McAfee Labs" fullword ascii wide
      $fp6 = "Kaspersky Lab" fullword ascii wide
      $fp7 = "<propertiesmap>" ascii wide  /* KasperSky Lab XML profiles */
      $fp10 = "Avira Engine Module" wide /* Program Files (x86)/Avira/Antivirus/aeheur.dll */
      $fp11 = "syntevo GmbH" wide fullword /* Program Files (x86)/DeepGit/bin/deepgit64.exe */
      $fp13 = "SophosClean" ascii /* ProgramData/Sophos/Update Manager/Update Manager/Warehouse/4d7da8cfbfbb16664dac79e78273a1e8x000.dat */
      $fp14 = "SophosHomeClean" wide
   condition:
      1 of ($x*)
      and not 1 of ($fp*)
      and not uint16(0) == 0xb0b0 // AV sigs file
      and not uint16(0) == 0x5953 // AV sigs file
}

