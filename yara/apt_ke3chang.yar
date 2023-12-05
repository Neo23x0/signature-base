rule APT_KE3CHANG_TMPFILE: APT KE3CHANG TMPFILE {
   meta:
      description = "Detects Strings left in TMP Files created by K3CHANG Backdoor Ketrican"
      author = "Markus Neis, Swisscom"
      reference = "https://app.any.run/tasks/a96f4f9d-c27d-490b-b5d3-e3be0a1c93e9/"
      date = "2020-06-18"
      hash1 = "4ef11e84d5203c0c425d1a76d4bf579883d40577c2e781cdccc2cc4c8a8d346f"
      id = "84d411af-ea3d-5862-8c2f-7caca60c1b66"
   strings:
      $pps1 = "PSParentPath             : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
      $pps2 = "PSPath                   : Microsoft.PowerShell.Core\\Registry::HKEY_CURRENT_USE" fullword ascii
      $psp1 = ": Microsoft.PowerShell.Core\\Registry" ascii

      $s4 = "PSChildName  : PhishingFilter" fullword ascii
      $s1 = "DisableFirstRunCustomize : 2" fullword ascii
      $s7 = "PSChildName  : 3" fullword ascii
      $s8 = "2500         : 3" fullword ascii

   condition:
      uint16(0) == 0x5350 and filesize < 1KB and $psp1 and 1 of ($pps*) and 1 of ($s*)
}

rule APT_MAL_Ke3chang_Ketrican_Jun20_1 {
   meta:
      description = "Detects Ketrican malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "BfV Cyber-Brief Nr. 01/2020"
      date = "2020-06-18"
      hash1 = "02ea0bc17875ab403c05b50205389065283c59e01de55e68cee4cf340ecea046"
      hash2 = "f3efa600b2fa1c3c85f904a300fec56104d2caaabbb39a50a28f60e0fdb1df39"
      id = "ccd8322e-c822-512a-9ac5-eabc9d09640b"
   strings:
      $xc1 = { 00 59 89 85 D4 FB FF FF 8B 85 D4 FB FF FF 89 45
               FC 68 E0 58 40 00 8F 45 FC E9 }

      $op1 = { 6a 53 58 66 89 85 24 ff ff ff 6a 79 58 66 89 85 }
      $op2 = { 8d 45 bc 50 53 53 6a 1c 8d 85 10 ff ff ff 50 ff }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 300KB and
      1 of ($x*) or 2 of them
}
