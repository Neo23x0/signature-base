import "pe"

rule MAL_Ransomware_Wadhrama {
   meta:
      description = "Detects Wadhrama Ransomware via Imphash"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-04-07"
      hash1 = "557c68e38dce7ea10622763c10a1b9f853c236b3291cd4f9b32723e8714e5576"
   condition:
      uint16(0) == 0x5a4d and pe.imphash() == "f86dec4a80961955a89e7ed62046cc0e"
}
