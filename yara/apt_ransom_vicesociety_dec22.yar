
rule APT_MAL_RANSOM_ViceSociety_PolyVice_Jan23_1 {
   meta:
      description = "Detects NTRU-ChaChaPoly (PolyVice) malware used by Vice Society"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
      date = "2023-01-12"
      modified = "2023-01-13"
      score = 75
      hash1 = "326a159fc2e7f29ca1a4c9a64d45b76a4a072bc39ba864c49d804229c5f6d796"
      hash2 = "8c8cb887b081e0d92856fb68a7df0dabf0b26ed8f0a6c8ed22d785e596ce87f4"
      hash3 = "9d9e949ecd72d7a7c4ae9deae4c035dcae826260ff3b6e8a156240e28d7dbfef"
      id = "e450407c-6c21-56bf-aedf-8e7f3890abe2"
   strings:
      $x1 = "C:\\Users\\root\\Desktop\\niX\\CB\\libntru\\" ascii
      
      $s1 = "C:\\Users\\root" ascii fullword
      $s2 = "#DBG: target = %s" ascii fullword
      $s3 = "# ./%s [-p <path>]/[-f <file> ] [-e <enc.extension>] [-m <requirements file name>]" ascii fullword
      $s4 = "### ################# ###" ascii fullword

      $op1 = { 89 ca 41 01 fa 89 ef 8b 6c 24 24 44 89 c9 09 d1 44 31 e6 89 c8 }
      $op2 = { bd 02 00 00 00 29 cd 48 0f bf d1 8b 44 46 02 01 44 53 02 8d 54 0d 00 83 c1 02 48 0f bf c2 }
      $op3 = { 48 29 c4 4c 8d 74 24 30 4c 89 f1 e8 46 3c 00 00 84 c0 41 89 c4 0f 85 2b 02 00 00 0f b7 45 f2 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and (
         1 of ($x*) 
         or 2 of them
      ) or 4 of them
}

rule APT_MAL_RANSOM_ViceSociety_Chily_Jan23_1 {
   meta:
      description = "Detects Chily or SunnyDay malware used by Vice Society"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.sentinelone.com/labs/custom-branded-ransomware-the-vice-society-group-and-the-threat-of-outsourced-development/"
      date = "2023-01-12"
      score = 80
      hash1 = "4dabb914b8a29506e1eced1d0467c34107767f10fdefa08c40112b2e6fc32e41"
      id = "1be4adb9-e60c-5023-9230-07f5fd16daaa"
   strings:
      $x1 = ".[Chily@Dr.Com]" ascii fullword

      $s1 = "localbitcoins.com/buy_bitcoins'>https://localbitcoins.com/buy_bitcoins</a>" ascii fullword
      $s2 = "C:\\Users\\root\\Desktop" ascii fullword
      $s3 = "for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"" wide fullword
      $s4 = "cd %userprofile%\\documents\\" wide
      $s5 = "noise.bmp" wide fullword
      $s6 = " Execution time: %fms (1sec=1000ms)" ascii fullword
      $s7 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide fullword

      $op1 = { 4c 89 c5 89 ce 89 0d f5 41 02 00 4c 89 cf 44 8d 04 49 0f af f2 89 15 e9 41 02 00 44 89 c0 }
      $op2 = { 48 8b 03 48 89 d9 ff 50 10 84 c0 0f 94 c0 01 c0 48 83 c4 20 5b }
      $op3 = { 31 c0 47 8d 2c 00 45 85 f6 4d 63 ed 0f 8e ec 00 00 00 0f 1f 80 00 00 00 00 0f b7 94 44 40 0c 00 00 83 c1 01 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 500KB and (
         1 of ($x*)
         or 3 of them
      )
      or 4 of them
}

