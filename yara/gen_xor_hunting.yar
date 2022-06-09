
rule SUSP_XORed_Mozilla {
   meta:
      description = "Detects suspicious single byte XORed keyword 'Mozilla/5.0' - it uses yara's XOR modifier and therefore cannot print the XOR key. You can use the CyberChef recipe linked in the reference field to brute force the used key."
      author = "Florian Roth"
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
      score = 55
   strings:
      $xo1 = "This program cannot be run in DOS mode" xor ascii wide
      $xo2 = "This program must be run under Win32" xor ascii wide
      $xof1 = "This program cannot be run in DOS mode" ascii wide
      $xof2 = "This program must be run under Win32" xor ascii wide
   condition:
      1 of ($xo*) and not 1 of ($xof*)
}
