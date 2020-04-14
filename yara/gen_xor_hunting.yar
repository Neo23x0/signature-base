
rule SUSP_XORed_Mozilla {
   meta:
      description = "Detects suspicious XORed keyword - Mozilla/5.0"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-28"
      score = 65
   strings:
      $xo1 = "Mozilla/5.0" xor(0x01-0xff) ascii wide
   condition:
      $xo1
}

rule SUSP_XORed_MSDOS_Stub_Message {
   meta:
      description = "Detects suspicious XORed MSDOS stub message"
      author = "Florian Roth"
      reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
      date = "2019-10-28"
      score = 55
   strings:
      $xo1 = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
      $xo2 = "This program must be run under Win32" xor(0x01-0xff) ascii wide
   condition:
      1 of ($xo*)
}
