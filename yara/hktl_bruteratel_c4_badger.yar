
rule HKTL_BruteRatel_Badger_Indicators_Oct22_4 {
   meta:
      description = "Detects Brute Ratel C4 badger indicators"
      author = "Matthew @embee_research, Florian Roth"
      reference = "https://twitter.com/embee_research/status/1580030310778953728"
      date = "2022-10-12"
      score = 75
      id = "a62d08ae-0fb3-55e9-b6f8-7940f8032e4a"
   strings:
      $s1 = { b? 89 4d 39 8c }
      $s2 = { b? bd ca 3b d3 }
      $s3 = { b? b2 c1 06 ae } 
      $s4 = { b? 74 eb 1d 4d }
   condition:
      filesize < 8000KB 
      and all of ($s*)
      and not uint8(0) == 0x02 /* SHC files */
}
