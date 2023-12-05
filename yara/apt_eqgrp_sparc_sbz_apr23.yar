
rule SUSP_ELF_SPARC_Hunting_SBZ_Obfuscation {
   meta:
   description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
   author = "netadr, modified by Florian Roth to avoid elf module import"
   reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
   date = "2023-04-02"
   modified = "2023-05-08"
   score = 60

   id = "15ee9a66-d823-508c-a14c-2c6ff45f47e5"
   strings:
      // xor g3, 0x47, o5
      // xor o5, g1, o5
      // xor g2, o5, o5
      $xor_block = { 9A 18 E0 47 9A 1B 40 01 9A 18 80 0D }

      $a1 = "SUNW_"

   condition:
      uint32be(0) == 0x7f454c46
      and $a1
      and $xor_block
}

rule SUSP_ELF_SPARC_Hunting_SBZ_UniqueStrings {
   meta:
      description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
      author = "netadr, modified by Florian Roth for performance reasons"
      reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
      date = "2023-04-02"
      modified = "2023-05-08"
      score = 60

      id = "d2f70d10-412e-5e83-ba4f-eac251012dc1"
   strings:
      $s1 = "<%u>[%s] Event #%u: "
      /* $s2 = "ofn" */
      $s2 = "lprc:%08X" ascii fullword

      // suggested by https://twitter.com/adulau/status/1553401532514766848
      $s3 = "diuXxobB" 
      $s4 = "CHM_FW"

   condition:
      2 of ($*)
}

rule SUSP_ELF_SPARC_Hunting_SBZ_ModuleStruct {
   meta:
      description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
      author = "netadr, modified by Florian Roth for FP reduction reasons"
      reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
      date = "2023-04-02"
      modified = "2023-05-08"
      score = 60

      id = "909746f1-44f5-597b-bdb2-2a1396d4b8c7"
   strings:
      $be = { 02 02 00 00 01 C1 00 07 }
      $le = { 02 02 00 00 07 00 C1 01 }

   condition:
      uint32be(0) == 0x7f454c46 and ( $be or $le )
}

