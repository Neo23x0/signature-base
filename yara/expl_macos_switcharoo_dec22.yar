
rule EXPL_HKTL_macOS_Switcharoo_CVE_2022_46689_Dec22 {
   meta:
      description = "Detects POCs that exploit privilege escalation vulnerability CVE-2022-46689 on macOS"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-12-19"
      score = 80
      hash1 = "64acd79a37b6f8443250dd33e95bd933ee39fc6d4f35ba6a987dae878d017386"
      hash2 = "6c2ace75000de8a7e8786f28b1b41eed72816991a0961475c6800753bfe9278c"
      hash3 = "6ce080b236ea3aa3b4c992d12af99445ab800abc709c6abbef852a9f0cf219b6"
      hash4 = "83cc4d72686aedf5218f07e60e759b4849b368975b70352dbba6fac4e8cde72b"
      hash5 = "a7b7fcfd609ff653d32c133417c0d3ffd9f581fb6de05ddbdead4d36cb6e3cc2"
      hash6 = "b2a97edb0ddc30ecc1a0b0c0739820bbef787394b44ab997393475de2ebf7b60"
      hash7 = "c7a64c6da5cf5046ae5c683d0264a32027110a2736b4c1b0df294e29a061a865"
      hash8 = "d517cde0d45e6930336538c89b310d5d540a66c921bf6f6f9b952e721b2f6a11"
      hash9 = "d53a559ea9131fe42eacf51431da3adde5a8fd5c2f3198f0d5451ef62ed33888"
      id = "25c551f7-48ae-5e71-b86e-68fb440262e5"
   strings:
      $x1 = "vm_read_overwrite: KERN_SUCCESS:%d KERN_PROTECTION_FAILURE:%d other:%d" ascii fullword
      $x2 = "Execting: %s (posix_spawn returned: %d)" ascii fullword
      $x3 = "/usr/bin/sed -e \"s/rootok/permit/g\" /etc" ascii fullword
      $x4 = "vm_unaligned_copy_switch_race" ascii fullword
      
      $s1 = "RO mapping was modified" ascii fullword
      $s2 = "Ran %d times in %ld seconds with no failure" ascii fullword

      $opa1 = { 4c 89 ee 31 c9 41 b8 00 40 00 00 6a 01 41 5c 41 54 6a 03 58 }
      $opa2 = { e8 ?? 01 00 00 48 8b 05 ?? 0? 00 00 8b 38 48 8b 13 44 8b 4b 14 48 83 ec 08 4c 89 ee 31 c9 }
      $opa3 = { 48 89 45 c8 48 8d 43 08 48 89 45 d0 4c 8b 7d c8 4c 8b 6d d0 6a 64 41 5e 80 7b 60 00 }

      $opb1 = { 55 48 89 e5 48 83 ec 60 48 8b 05 ?1 06 00 00 48 8b 00 48 89 45 f8 0f 28 05 ?b 07 00 00 48 8d 75 d0 }
   condition:
      ( filesize < 400KB and 1 of ($x*) ) or
      (
         ( uint16(0) == 0xfacf or ( uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca ) ) and 
         filesize < 400KB and
         2 of them
      )
}

rule EXPL_macOS_Switcharoo_Indicator_Dec22 {
   meta:
      description = "Detects indicators found after exploitations of CVE-2022-46689"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/zhuowei/MacDirtyCowDemo"
      date = "2022-12-19"
      score = 65
      id = "d5d9559a-c19c-5ddc-9d72-701986a9d7ac"
   strings:
      $x1 = "auth       sufficient     pam_permit.so" ascii
   condition:
      filesize < 1KB and $x1
}
