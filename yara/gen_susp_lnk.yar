
rule SUSP_LNK_Big_Link_File {
   meta:
      description = "Detects a suspiciously big LNK file - maybe with embedded content"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-15"
      score = 65
      id = "e130f213-53fc-56d6-b1d5-0508a7e18e61"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and filesize > 200KB
}
