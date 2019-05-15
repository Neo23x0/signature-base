
rule MAL_RANSOM_RobinHood_May19_1 {
   meta:
      description = "Detects RobinHood Ransomware"
      author = "Florian Roth"
      reference = "https://twitter.com/BThurstonCPTECH/status/1128489465327030277"
      date = "2019-05-15"
      hash1 = "21cb84fc7b33e8e31364ff0e58b078db8f47494a239dc3ccbea8017ff60807e3"
   strings:
      $s1 = ".enc_robbinhood" ascii
      $s2 = "c:\\windows\\temp\\pub.key" ascii fullword
      $s3 = "cmd.exe /c net use * /DELETE /Y" ascii
      $s4 = "sc.exe stop SQLAgent$SQLEXPRESS" nocase
      $s5 = "main.EnableShadowFucks" nocase
      $s6 = "main.EnableRecoveryFCK" nocase
      $s7 = "main.EnableLogLaunders" nocase
      $s8 = "main.EnableServiceFuck" nocase
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}
