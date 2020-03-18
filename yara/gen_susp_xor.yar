/* requires YARA 3.8 or higher */

rule SUSP_XORed_URL_in_EXE {
   meta:
      description = "Detects an XORed URL in an executable"
      author = "Steve Miller, Florian Roth"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      score = 50
   strings:
      $s1 = "http://" xor
      $s2 = "https://" xor
      $f1 = "http://" ascii
      $f2 = "https://" ascii
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and (
         ( $s1 and #s1 > #f1 ) or
         ( $s2 and #s2 > #f2 )
      )
}
