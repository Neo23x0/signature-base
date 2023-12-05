rule SUSP_VulnDriver_HP_Hardware_Diagnostics_Etdsupp_May23 {
   meta:
      description = "Detects vulnerable versions of the HP Hardware Diagnostics driver (etdsupp.sys) based on PE metadata info"
      author = "X__Junior (Nextron Systems)"
      date = "2023-05-12"
      reference = "https://github.com/alfarom256/HPHardwareDiagnostics-PoC/tree/main/"
      hash = "f744abb99c97d98e4cd08072a897107829d6d8481aee96c22443f626d00f4145"
      score = 65
      id = "8f838e4f-3e3e-5131-9d67-e49f6848bb37"
    strings:
        $s1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 65 00 74 00 64 00 73 00 75 00 70 00 70 00 2e 00 73 00 79 00 73 00} /*OriginalFilename  etdsupp.sys*/
        $s2 = "etdsupp.pdb"
        $s3 = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff]{2}[\x00-\x11]\x00[\x00-\xff]{4}|\x00\x00\x12\x00\x00\x00\x00\x00)/  /* Vuln Versions*/
    condition:
        uint16(0) == 0x5a4d and int16(uint32(0x3C) + 0x5c) == 0x0001 and filesize < 100KB and all of them
}
