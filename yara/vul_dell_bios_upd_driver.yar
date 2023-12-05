
rule VULN_Dell_BIOS_Update_Driver_DBUtil_May21 {
   meta:
      description = "Detects vulnerable DELL BIOS update driver that allows privilege escalation as reported in CVE-2021-21551 - DBUtil_2_3.Sys - note: it's usual location is in the C:\\Windows\\Temp folder"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://labs.sentinelone.com/cve-2021-21551-hundreds-of-millions-of-dell-computers-at-risk-due-to-multiple-bios-driver-privilege-escalation-flaws/"
      date = "2021-05-05"
      score = 60
      hash1 = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5"
      hash2 = "ddbf5ecca5c8086afde1fb4f551e9e6400e94f4428fe7fb5559da5cffa654cc1"
      id = "6d46866e-40fb-5fbf-b159-6bf688e638cb"
   strings:
      $s1 = "\\DBUtilDrv2" ascii
      $s2 = "DBUtil_2_3.Sys" ascii fullword
      $s3 = "[ Dell BIOS Utility Driver - " ascii fullword
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and all of them
}
