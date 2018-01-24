
rule MAL_RTF_Embedded_OLE_PE {
   meta:
      description = "Detects a suspicious string often used in PE files in a hex encoded object stream"
      author = "Florian Roth"
      reference = "https://www.nextron-systems.com/2018/01/22/creating-yara-rules-detect-embedded-exe-files-ole-objects/"
      date = "2018-01-22"
   strings:
      /* Hex encoded strings */
      /* This program cannot be run in DOS mode */
      $a1 = "546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f6465" ascii
      /* KERNEL32.dll */
      $a2 = "4b45524e454c33322e646c6c" ascii
      /* C:\fakepath\ */
      $a3 = "433a5c66616b65706174685c" ascii
      /* DOS Magic Header */
      $m3 = "4d5a40000100000006000000ffff"
      $m2 = "4d5a50000200000004000f00ffff"
      $m1 = "4d5a90000300000004000000ffff"
   condition:
      uint32be(0) == 0x7B5C7274 /* RTF */
      and 1 of them
}
