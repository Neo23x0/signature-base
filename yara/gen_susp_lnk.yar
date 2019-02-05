
rule SUSP_LNK_Big_Link_File {
   meta:
      description = "Detects a suspiciously big LNK file - maybe with embedded content"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-15"
      score = 65
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and filesize > 200KB
}
