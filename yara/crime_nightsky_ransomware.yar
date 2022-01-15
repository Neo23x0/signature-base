

rule MAL_Nightsky_Ransomware {
   meta:
      description = "Detects strings known from Nightsky Ransomware"
      author = "Xanderux"
      reference = "https://cuckoo.cert.ee/analysis/2612528/summary"
      date = "2022-01-15"
      hash = "1fca1cd04992e0fcaa714d9dfa97323d81d7e3d43a024ec37d1c7a2767a17577"
   strings:
      $x1 = "\\Users\\IEUser\\Desktop\\nightsky.exe" fullword
      $x2 = "gg5ryfgogainisskdvh4y373ap3b2mxafcibeh2lvq5x7fx76ygcosad.onion" fullword
      $x3 = "yourcompanyhasbeenhackedbyus" fullword
      $x4 = "nightsky.cyou" fullword
   condition:
      uint16(0) == 0x5a4d and 
      filesize > 8MB and
      all of them
}
