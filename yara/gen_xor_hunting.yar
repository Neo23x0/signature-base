
rule SUSP_XORed_Mozilla {
   meta:
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gchq.github.io/CyberChef/#recipe=XOR_Brute_Force()"
      date = "2019-10-28"
      modified = "2022-05-13"
      score = 65
   strings:
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xof1 = "Mozilla/5.0" ascii wide

      $fp1 = "Sentinel Labs" wide
      $fp2 = "<filter object at" ascii /* Norton Security */
   condition:
      $xo1 and not $xof1 and not 1 of ($fp*)
}

rule SUSP_XORed_MSDOS_Stub_Message {
   meta:
      description = "Detects suspicious XORed MSDOS stub message"
      author = "Florian Roth"
      reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
      date = "2019-10-28"
      modified = "2023-09-04"
      score = 55
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
   condition:
      1 of ($x*)
      and not 1 of ($fp*)
      and not uint16(0) == 0xb0b0
      and not uint16(0) == 0x5953
}
