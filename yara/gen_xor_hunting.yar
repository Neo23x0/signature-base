
rule SUSP_XORed_Mozilla {
   meta:
      description = "Detects suspicious XORed keyword - Mozilla/5.0"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-10-28"
      score = 65
   strings:
      $xo1 = "Mozilla/5.0" xor ascii wide
      $xof1 = "Mozilla/5.0" ascii wide
   condition:
      $xo1 and not $xof1
}
