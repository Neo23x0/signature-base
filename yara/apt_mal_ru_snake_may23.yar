/* 
  Rule that uses the byte chains included in the Volatility Plugin published
  by CSA in a YARA rule

  code from the plugin:
  
  strings_to_find = [
    b'\x25\x73\x23\x31',
    b'\x25\x73\x23\x32',
    b'\x25\x73\x23\x33',
    b'\x25\x73\x23\x34',
    b'\x2e\x74\x6d\x70', 
    b'\x2e\x73\x61\x76',
    b'\x2e\x75\x70\x64']
*/

rule APT_MAL_RU_WIN_Snake_Malware_May23_1 {
    meta:
        author = "Matt Suiche (Magnet Forensics)"
        description = "Hunting Russian Intelligence Snake Malware"
        date = "2023-05-10"
        modified = "2025-03-21"
        threat_name = "Windows.Malware.Snake"
        reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
        score = 70
        scan_context = "memory"
        license = "MIT"

    /* The original search only query those bytes in PAGE_EXECUTE_WRITECOPY VADs */
        id = "53d2de3c-350c-5090-84bb-b6cde16a80ad"
    strings:
        $a = { 25 73 23 31 }
        $b = { 25 73 23 32 }
        $c = { 25 73 23 33 }
        $d = { 25 73 23 34 }
        $e = { 2e 74 6d 70 }
        /* $f = { 2e 74 6d 70 } */
        $g = { 2e 73 61 76 }
        $h = { 2e 75 70 64 }
    condition:
        all of them
}


rule APT_MAL_RU_Snake_Indicators_May23_1 {
   meta:
      description = "Detects indicators found in Snake malware samples"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
      date = "2023-05-10"
      score = 85
      hash1 = "10b854d66240d9ee1ce4296d2f7857d2b1c6f062ca836d13d777930d678b3ca6"
      hash2 = "15ac5a61fb3e751045de2d7f5ff26c673f3883e326cd1b3a63889984a4fb2a8f"
      hash3 = "315ec991709eb45eccf724dfe31bccb7affcac7f8e8007e688ba8d02827205e0"
      hash4 = "417eb4fb9ada270af35562ff317807ac5ca9ee26181fe89990858f0944d3a6a7"
      hash5 = "48112970de6ea0f925f0657b30adcd0723df94afc98cfafdc991d70ad3602119"
      hash6 = "55ea557bcf4c143f20c616abe9075f7faafbf825aeef9ddb4f2b201acc44414b"
      hash7 = "6568bbeeb417e1111bf284e73152d90fe17e5497da7630ccddcbc666730dccef"
      hash8 = "81d620cb645006ffc9ac1b9d98a53aa286ae92b025bda075962079633f020482"
      hash9 = "888a3029b1b8b664eb1fc77dd511c4088a1e28ae5535a8683642bb3dca011d00"
      hash10 = "9027b4fef50b36289d630059425dc1137c88328329c3ea9dbc348dccd001adc0"
      hash11 = "9ac199572cab67433726976a0e9ba39d6feed1d567d6d230ebe3133df8dcb7fa"
      hash12 = "a64e5d872421991226ee040b4cd49a89ca681bdef4c10c4798b6c7b5c832c6df"
      hash13 = "b5d2da5eb57b5ab26edb927469552629f3cf43bbce2b1a128f6daac7cf57f6f7"
      hash14 = "bc15de1d1c6c62c0bf856e0368adabc4941e7b687a969912494c173233e6d28d"
      hash15 = "bdf94311313c39a3413464f623bd75a3db2eb05cc01090acd6dcd462a605eb4a"
      hash16 = "e4311892ae00bf8148a94fa900fc8e2c279a2acd3b4b4b4c3d0c99dd1d32353c"
      hash17 = "ed74288b367a93c6b47343bc696e751b9c465761ce9c4208901726baa758b234"
      hash18 = "ef1f1c7692b92a730f76b6227643b2d02a6e353af6e930166e3b48e3903e4ffd"
      hash19 = "f5e982b76af7f447742753f0b57eec3d7dd2e3c8e5506c35d4cf6c860b829f45"
      id = "0d4fa8a7-447c-5905-bab9-b63de6209036"
   strings:
      $s1 = "\\\\.\\%s\\\\" ascii fullword
      $s2 = "read_peer_nfo" ascii fullword
      $s3 = "rcv_buf=%d%c" ascii fullword
      $s4 = "%s: (0x%08x)" ascii fullword
      $s5 = "no_impersonate" ascii fullword
   condition:
      all of them
}



