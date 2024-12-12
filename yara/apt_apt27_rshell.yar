
rule APT_MAL_APT27_Rshell_Jul24 {
   meta:		
      sharing = "TLP:WHITE"
      source = "BUNDESAMT FUER VERFASSUNGSSCHUTZ"
      author = "Bundesamt fuer Verfassungsschutz, modified by Florian Roth"
      description = "YARA rule to detect RSHELL of APT27"
      category = "MALWARE"
      malware = "RSHELL / SYSUPDATE"
      reference = "https://x.com/bfv_bund/status/1811364839656185985?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
      date = "2024-07-11"
      hash1 = "0433edfad648e1e29be54101abaded690302dc7e49ad916cfbbddf99b3ade12c"
      hash2 = "10bb89fdf25c88d3c5623e8d68573124c9a42549750014e3675e2ca342aeba4a"
      hash3 = "2603e1f61363451891c97b0c4ce8acfbfb680d3df4282f9d151ecce3a5679616"
      hash4 = "70dac42491f8f19568a5d7b1d10b29f732a88d75e7f2bfa07b23202bacadf56f"
      hash5 = "b988a6583ce40f07e5fc8e890ae2b1c84a93db8a2e3ca8769241b94bea332a7a"
      hash6 = "c4fe1e56f601d411e2385352606524fb8bbf773bc2ba14889a8de605c2d14da0"
      hash7 = "c787144d285fcca8a542f7a5525a37bcd089b39068b9a4db7fe3554ee6c08301"
      hash8 = "ddaa4d23e4651a517fffbd29f0924607ba6b6253171144da5e49237afe91666b"
      id = "67c8ac4e-8e2f-5cca-90cb-5d5fdf6f86b5"
   strings:
      $a1 = "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%" ascii
      $a2 = "/proc/self/exe" ascii

      $s1 = "HISTFILE" ascii fullword
      $s2 = "/tmp/guid" ascii fullword

      $sop1 = { e8 ?? ?? ?? ?? c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? }
      $sop2 = { c7 43 04 00 00 00 00 8b 3b 85 ff 7e 2? e8 ?? ?? 0? 00 85 c0 7e 0? f7 d8 }
   condition:
      (
         uint32be(0) == 0x7f454c46 // Linux
         or ( uint32be(0) == 0xcafebabe and uint32be(4) < 0x20 ) // Universal mach-O App with dont-match-java-class-file hack
         or uint32(0) == 0xfeedface // 32-bit mach-O
         or uint32(0) == 0xfeedfacf // 64-bit mach-O
      )
      and filesize < 2MB 
      and all of ($a*)
      and 2 of ($s*)
      or 3 of ($s*)
}
