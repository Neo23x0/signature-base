rule SUSP_EXPL_CommVault_CVE_2025_57791_Aug25_1 {
   meta:
      description = "Detects potential exploit for WT-2025-0050, authentication bypass through QCommand argument injection"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      author = "X__Junior"
      date = "2025-08-21"
      score = 60
   strings:
      $sa1 = "_localadmin__"
      $sa2 = "-localadmin"
   condition:
      not uint16(0) == 0x5a4d and
      filesize < 20MB and all of them
}

rule SUSP_EXPL_CommVault_CVE_2025_57791_Aug25_2 {
   meta:
      description = "Detects potential exploit for WT-2025-0050, authentication bypass through QCommand argument injection"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      author = "X__Junior"
      date = "2025-08-21"
      score = 65
   strings:
      $sa1 = "_localadmin__"
      $sa2 = "-localadmin" base64
   condition:
      filesize < 20MB and all of them
}

rule SUSP_EXPL_CommVault_CVE_2025_57791_Artifact_Aug25 {
   meta:
      description = "Detects exploit artifact for WT-2025-0050, authentication bypass through QCommand argument injection"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      author = "X__Junior"
      date = "2025-08-21"
      score = 75
   strings:
      $sa1 = "_localadmin__"
      $sa2 = /-cs [a-zA-Z0-9-{}]{3,32} -cs /

      $sb2 = "-localadmin" base64
      $sb1 = "-localadmin"
   condition:
      filesize < 20MB and all of ($sa*) and 1 of ($sb*)
}

rule EXPL_JSP_CommVault_CVE_2025_57791_Aug25_1 {
   meta:
      description = "Detects potential exploit for WT-2025-0049, Post-Auth RCE with QCommand Path Traversal"
      author = "X__Junior"
      date = "2025-08-21"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      score = 75
   strings:
      $s1 = "<App_GetUserPropertiesResponse>" ascii
      $s2 = "getMethod('getRuntime').invoke(null).exec(param.cmd)" ascii
   condition:
      filesize < 50KB and all of them
}

rule EXPL_JSP_CommVault_CVE_2025_57791_Aug25_2 {
   meta:
      description = "Detects potential exploit for WT-2025-0049, Post-Auth RCE with QCommand Path Traversal"
      author = "X__Junior"
      date = "2025-08-21"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      score = 75
   strings:
      $s1 = "<App_UpdateUserPropertiesRequest>" ascii
      $s2 = "<description>" ascii
      $s3 = "getMethod('getRuntime').invoke(null).exec(param.cmd)" ascii
   condition:
      filesize < 50KB and all of them
}

rule EXPL_LOG_CommVault_CVE_2025_57791_Indicator_Shell_Drop_Aug25 {
   meta:
      description = "Detects suspicious log lines that indicate web shell drops into the Apache root folder of a Commvault installation"
      author = "Florian Roth"
      reference = "https://labs.watchtowr.com/guess-who-would-be-stupid-enough-to-rob-the-same-vault-twice-pre-auth-rce-chains-in-commvault/"
      date = "2025-08-21"
      score = 70
   strings:
      $xr1 = /Results written to \[[C-Z]:\\Program Files\\Commvault\\ContentStore\\Apache\\webapps\\ROOT\\[^\\]{1,20}\.jsp\]/  // https://regex101.com/r/KV8iK6/1
   condition:
      $xr1
}
