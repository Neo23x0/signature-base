
rule SUSP_BAT_OBFUSC_Jul24_1 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
   strings:
      $s1 = "&&set "
   condition:
      filesize < 300KB  
      and uint32(0) == 0x20746573 // "set " at the beginning of the file
      and $s1 in (0..32) // "&&set " in the first 32 bytes
}

rule SUSP_BAT_OBFUSC_Jul24_2 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
   strings:
      $s1 = "&&set "
   condition:
      filesize < 300KB
      // number of occurrences of the string "&&set " in the file
      and #s1 > 30
      // it's the "%\n" at the very end of the file
      and uint16(filesize-2) == 0x0a0d
      and uint8(filesize-3) == 0x25
}

rule SUSP_BAT_OBFUSC_Jul24_3 {
   meta:
      description = "Detects indicators of obfuscation in Windows Batch files"
      author = "Florian Roth"
      reference = "https://x.com/0xToxin/status/1811656147943752045"
      date = "2024-07-12"
      score = 70
   strings:
      $s1 = "% \\\\%" // part of the UNC path for the SMB connection
      // It detects the set pattern with a single character value in front of the %%
      // we use ?? to wildcard the character
      // =?&&set 
      $s2 = { 3D ?? 26 26 73 65 74 20 } 
   condition:
      filesize < 300KB
      and all of them
}
