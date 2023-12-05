
rule MAL_RANSOM_LNX_macOS_LockBit_Apr23_1 {
   meta:
      description = "Detects LockBit ransomware samples for Linux and macOS"
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1647384505550876675?s=20"
      date = "2023-04-15"
      hash1 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
      hash2 = "9ebcbaf3c9e2bbce6b2331238ab584f95f7ced326ca4aba2ddcc8aa8ee964f66"
      hash3 = "a405d034c01a357a89c9988ffe8a46a165915df18fd297469b2bcaaf97578442"
      hash4 = "c9cac06c9093e9026c169adc3650b018d29c8b209e3ec511bbe34cbe1638a0d8"
      hash5 = "dc3d08480f5e18062a0643f9c4319e5c3f55a2e7e93cd8eddd5e0c02634df7cf"
      hash6 = "e77124c2e9b691dbe41d83672d3636411aaebc0aff9a300111a90017420ff096"
      hash7 = "0be6f1e927f973df35dad6fc661048236d46879ad59f824233d757ec6e722bde"
      hash8 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"
      score = 85
      id = "c01cb907-7d30-5487-b908-51f69ddb914c"
   strings:
      $x1 = "restore-my-files.txt" ascii fullword

      $s1 = "ntuser.dat.log" ascii fullword
      $s2 = "bootsect.bak" ascii fullword
      $s3 = "autorun.inf" ascii fullword
      $s4 = "lockbit" ascii fullword 

      $xc1 = { 33 38 36 00 63 6D 64 00 61 6E 69 00 61 64 76 00 6D 73 69 00 6D 73 70 00 63 6F 6D 00 6E 6C 73 } /* extensions that get encrypted */
      $xc2 = { 6E 74 6C 64 72 00 6E 74 75 73 65 72 2E 64 61 74 2E 6C 6F 67 00 62 6F 6F 74 73 65 63 74 2E 62 61 6B } /* file name list */
      $xc3 = { 76 6D 2E 73 74 61 74 73 2E 76 6D 2E 76 5F 66 72 65 65 5F 63 6F 75 6E 74 00 61 2B 00 2F 2A } /* vm.stats + short strings */

      $op1 = { 84 e5 f0 00 f0 e7 10 40 2d e9 2e 10 a0 e3 00 40 a0 e1 ?? fe ff }
      $op2 = { 00 90 a0 e3 40 20 58 e2 3f 80 08 e2 3f 30 c2 e3 09 20 98 e1 08 20 9d }
      $op3 = { 2d e9 01 70 43 e2 07 00 13 e1 01 60 a0 e1 08 d0 4d e2 02 40 }
   condition:
      ( uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca )
      and ( 
         1 of ($x*)
         or 3 of them
      ) 
      or 2 of ($x*)
      or 5 of them
}

rule MAL_RANSOM_LockBit_Apr23_1 {
   meta:
      description = "Detects indicators found in LockBit ransomware"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "75dc8b95-16f0-5170-a7d6-fc10bb778348"
   strings:
      $xe1 = "-i '/path/to/crypt'" xor
      $xe2 = "http://lockbit" xor
      
      $s1 = "idelayinmin" ascii
      $s2 = "bVMDKmode" ascii
      $s3 = "bSelfRemove" ascii
      $s4 = "iSpotMaximum" ascii

      $fp1 = "<html"
   condition:
      (
         1 of ($x*)
         or 4 of them
      )
      and not 1 of ($fp*)
}

rule MAL_RANSOM_LockBit_Locker_LOG_Apr23_1 {
   meta:
      description = "Detects indicators found in LockBit ransomware log files"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "aa0a2393-e5a2-5151-8afb-91a9bb922179"
   strings:
      $s1 = " is encrypted. Checksum after encryption "
      $s2 = "~~~~~Hardware~~~~"
      $s3 = "[+] Add directory to encrypt:"
      $s4 = "][+] Launch parameters: "
   condition:
      2 of them
}

rule MAL_RANSOM_LockBit_ForensicArtifacts_Apr23_1 {
   meta:
      description = "Detects forensic artifacts found in LockBit intrusions"
      author = "Florian Roth"
      reference = "https://objective-see.org/blog/blog_0x75.html"
      date = "2023-04-17"
      score = 75
      id = "e716030c-ee78-51dc-919c-cf59e93da976"
   strings:
      $x1 = "/tmp/locker.log" ascii fullword
      $x2 = "Executable=LockBit/locker_" ascii
      /* Tor Browser Links:\x0d\x0ahttp://lockbit */
      $xc1 = { 54 6F 72 20 42 72 6F 77 73 65 72 20 4C 69 6E 6B 73 3A 0D 0A 68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 }
   condition:
      1 of ($x*)
}
