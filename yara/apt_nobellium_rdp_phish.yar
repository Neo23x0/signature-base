
rule SUSP_RDP_File_Indicators_Oct24_1 {
   meta:
      description = "Detects characteristics found in malicious RDP files used as email attachments in spear phishing campaigns"
      author = "Florian Roth"
      reference = "https://thecyberexpress.com/rogue-rdp-files-used-in-ukraine-cyberattacks/"
      date = "2024-10-25"
      score = 75
      hash1 = "280fbf353fdffefc5a0af40c706377142fff718c7b87bc8b0daab10849f388d0"
      hash2 = "8b45f5a173e8e18b0d5c544f9221d7a1759847c28e62a25210ad8265f07e96d5"
      hash3 = "9b8cb8b01ce4eafb9204250a3c28bfaf70cc76a99ce411ad52bbf1aa2b6cce34"
      hash4 = "ba4d58f2c5903776fe47c92a0ec3297cc7b9c8fa16b3bf5f40b46242e7092b46"
      hash5 = "f357d26265a59e9c356be5a8ddb8d6533d1de222aae969c2ad4dc9c40863bfe8"
      id = "16128c1e-64ed-5a3e-ad1e-e0330d91f5a9"
   strings:
      $s1 = "redirectclipboard:i:1" wide fullword
      $s2 = "redirectprinters:i:1" wide fullword
      $s3 = "remoteapplicationmode:i:1" wide fullword
      $s4 = "username:s:" wide
      $s5 = "emoteapplicationicon:s:C:\\Windows\\SystemApps" wide
   condition:
      filesize < 50KB
      and all of them
}

