
rule SUSP_LNK_Suspicious_Folders_Jan25 {
   meta:
      description = "Detects link files (.LNK) with suspicious folders mentioned in the target path"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-01-24"
      score = 65
   strings:
      $x1 = "RECYCLER.BIN\\" wide
      $x2 = "Perflogs\\" wide
   condition:
      uint16(0) == 0x004c
      and 1 of them
}
