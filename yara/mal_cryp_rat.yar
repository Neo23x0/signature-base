import "pe"

rule MAL_CrypRAT_Jan19_1 {
   meta:
      description = "Detects CrypRAT"
      author = "Florian Roth (Nextron Systems)"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      reference = "Internal Research"
      score = 90
      date = "2019-01-07"
      id = "f3063a16-8813-5d6c-9807-6a0725907fb5"
   strings:
      $x1 = "Cryp_RAT" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
         pe.imphash() == "2524e5e9fe04d7bfe5efb3a5e400fe4b" or
         1 of them
      )
}
