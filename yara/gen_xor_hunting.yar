
rule SUSP_XORed_Mozilla_Oct19 {
   meta:
      old_rule_name = "SUSP_XORed_Mozilla"
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth"
      reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
      date = "2019-10-28"
      modified = "2023-11-03"
      score = 60
      id = "71e5b399-c384-5330-ae52-4e0a806e7969"
   strings:
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xof1 = "Mozilla/5.0" ascii wide

      $fpa1 = "Sentinel Labs" wide
      $fpa2 = "<filter object at" ascii /* Norton Security */

      $fpb1 = { 64 65 78 0a 30 33 35 } /* dex.035 */
   condition:
      $xo1 
      and not $xof1 
      and not 1 of ($fpa*)
      and not $fpb1 at 0
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

