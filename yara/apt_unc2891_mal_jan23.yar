
rule MAL_UNC2891_Caketap {
   meta:
      description = "Detects UNC2891 Rootkit Caketap"
      author = "Frank Boldewin (@r3c0nst)"
      date = "2022-03-30"
      reference = "https://github.com/fboldewin/YARA-rules/tree/master"

      id = "9c2ffe3d-69ca-5f93-bdb1-40e449139dec"
   strings:
      $str1  = ".caahGss187" ascii fullword // SyS_mkdir hook cmd ident
      $str2 = "ipstat" ascii // rootkit lkm name
      $code1 = {41 80 7E 06 4B 75 ?? 41 80 7E 07 57 75 ?? 41 0F B6 46 2B} // HSM cmd KW check
      $code2 = {41 C6 46 01 3D 41 C6 46 08 32} // mode_flag switch
   condition:
      uint32 (0) ==  0x464c457f and (all of ($code*) or (all of ($str*) and #str2 == 2))
}

rule MAL_UNC2891_Slapstick {
   meta:
      description = "Detects UNC2891 Slapstick pam backdoor"
      author = "Frank Boldewin (@r3c0nst), slightly modifier by Florian Roth"
      date = "2022-03-30"
      modified = "2023-01-05"
      reference = "https://github.com/fboldewin/YARA-rules/tree/master"
      hash1 = "9d0165e0484c31bd4ea467650b2ae2f359f67ae1016af49326bb374cead5f789"

      id = "eb5db507-ac12-5c11-9dd9-ec34b9a80e1c"
   strings:
      $code1 = {F6 50 04 48 FF C0 48 39 D0 75 F5} // string decrypter
      $code2 = {88 01 48 FF C1 8A 11 89 C8 29 F8 84 D2 0F 85} // log buf crypter
      $str1 = "/proc/self/exe" fullword ascii
      $str2 = "%-23s %-23s %-23s %-23s %-23s %s" fullword ascii
      $str3 = "pam_sm_authenticate" ascii
      /* $str4 = "ACCESS GRANTED & WELCOME" xor // pam prompt message */
      $str_fr1 = "HISTFILE=/dev/null" // replacement for XORED message for memory usage reasons
   condition:
      uint32 (0) ==  0x464c457f and filesize < 100KB and (all of ($code*) or all of ($str*))
}

rule MAL_UNC2891_Steelcorgi {
   meta:
      description = "Detects UNC2891 Steelcorgi packed ELF binaries"
      author = "Frank Boldewin (@r3c0nst)"
      date = "2022-03-30"
      reference = "https://github.com/fboldewin/YARA-rules/tree/master"
      hash1 = "0760cd30d18517e87bf9fd8555513423db1cd80730b47f57167219ddbf91f170"
      hash2 = "3560ed07aac67f73ef910d0b928db3c0bb5f106b5daee054666638b6575a89c5"
      hash3 = "5b4bb50055b31dbd897172583c7046dd27cd03e1e3d84f7a23837e8df7943547"
      
      id = "94da7da5-5fc3-5221-97d6-1854aa7b1959"
   strings:
      $pattern1 = {70 61 64 00 6C 63 6B 00} // padlck
      $pattern2 = {FF 72 FF 6F FF 63 FF 2F FF 73 FF 65 FF 6C FF 66 FF 2F FF 65 FF 78 FF 65} // proc_self_exe
      
   condition:
      uint32(0) == 0x464c457f and all of them
}

rule MAL_UNC2891_Winghook {
   meta:
      description = "Detects UNC2891 Winghook Keylogger"
      author = "Frank Boldewin (@r3c0nst)"
      date = "2022-03-30"
      reference = "https://github.com/fboldewin/YARA-rules/tree/master"
      hash1 = "d071ee723982cf53e4bce89f3de5a8ef1853457b21bffdae387c4c2bd160a38e"

      id = "e5955fa0-8204-58e3-88a6-de4b47756ede"
   strings:
      $code1 = {01 F9 81 E1 FF 00 00 00 41 89 CA [15] 44 01 CF 81 E7 FF 00 00 00} // crypt log file data
      $code2 = {83 E2 0F 0F B6 14 1? 32 14 01 88 14 0? 48 83 ?? ?? 48 83 ?? ?? 75} // decrypt path+logfile name
      $str1 = "fgets" ascii // hook function name
      $str2 = "read" ascii // hook function name
   condition:
      uint32 (0) ==  0x464c457f and filesize < 100KB and 1 of ($code*) and all of ($str*)
}
