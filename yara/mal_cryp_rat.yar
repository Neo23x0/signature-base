import "pe"

rule MAL_CrypRAT_Jan19_1 {
   meta:
      description = "Detects CrypRAT"
      author = "Florian Roth"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      reference = "Internal Research"
      score = 90
      date = "2019-01-07"
   strings:
      $x1 = "Cryp_RAT" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "2524e5e9fe04d7bfe5efb3a5e400fe4b" or
         1 of them
      )
}
