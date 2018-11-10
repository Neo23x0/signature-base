
rule SUSP_CMD_Var_Expansion {
   meta:
      description = "Detects Office droppers that include a variable expansion string"
      author = "Florian Roth"
      reference = "https://twitter.com/asfakian/status/1044859525675843585"
      date = "2018-09-26"
      score = 60
   strings:
      $a1 = " /V:ON" ascii wide fullword
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and $a1
}
