
rule HKTL_Khepri_Beacon_Sep21_1 {
   meta:
      description = "Detects Khepri C2 framework beacons"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/geemion/Khepri/"
      date = "2021-09-08"
      score = 90
      hash1 = "86c48679db5f4c085fd741ebec5235bc6cf0cdf8ef2d98fd8a689ceb5088f431"
      id = "b2c8aaf7-7953-55a3-8499-565800fa01f1"
   strings:
      $x1 = "NT %d.%d Build %d  ProductType:%s" ascii fullword

      /* c2.CMDPARAM.cmd */
      $xe1 = "YzIuQ01EUEFSQU0uY21k" ascii
      $xe2 = "MyLkNNRFBBUkFNLmNtZ" ascii
      $xe3 = "jMi5DTURQQVJBTS5jbW" ascii
      
      $sx1 = "c2.ProcessItem.user" ascii fullword
      $sx2 = "c2.CMDPARAM.cmd" ascii fullword
      $sx3 = "c2.DownLoadFile.file_path" ascii fullword

      $sa1 = "file size zero"
      $sa2 = "cmd.exe /c "
      $sa3 = "error parse param"
      $sa4 = "innet_ip"

      $op1 = { c3 b9 b4 98 49 00 87 01 5d c3 b8 b8 98 49 00 c3 8b ff }
      $op2 = { 8b f1 80 3d 58 97 49 00 00 0f 85 96 00 00 00 33 c0 40 b9 50 97 49 00 87 01 33 db }
      $op3 = { 90 d5 0c 43 00 34 0d 43 00 ea 0c 43 00 7e 0d 43 00 b6 0d 43 00 cc }
      $op4 = { 69 c0 ff 00 00 00 8b 4d c0 23 88 40 7c 49 00 89 4d c0 8b 45 cc 0b 45 c0 89 45 cc 8b 45 d0 }
   condition:
      ( uint16(0) == 0x5a4d or uint32be(0) == 0x7f454c46 ) and
      filesize < 2000KB and (
         1 of ($x*) or
         2 of ($sx*) or
         all of ($sa*) or 
         3 of ($op*)
      ) or (
         filesize < 10MB 
         and 1 of ($xe*)
      ) 
      or 5 of them
}
