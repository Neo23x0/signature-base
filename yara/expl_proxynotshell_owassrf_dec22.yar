
rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_1 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22"
      score = 70
   strings:
      $s1 = "/owa/mastermailbox%40outlook.com/powershell" ascii wide

      $sa1 = " 200 " ascii wide
      $sa2 = " POST " ascii wide

      // based on filters found in CrowdStrikes script https://github.com/CrowdStrike/OWASSRF/blob/main/Rps_Http-IOC.ps1
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition:
      all of ($s*) and not 1 of ($fp*)
}

rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_2 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22"
      score = 60
   strings:
      $sr1 = / \/owa\/[^\/\s]{1,30}(%40|@)[^\/\s\.]{1,30}\.[^\/\s]{2,3}\/powershell / ascii wide

      $sa1 = " 200 " ascii wide
      $sa2 = " POST " ascii wide

      // based on filters found in CrowdStrikes script https://github.com/CrowdStrike/OWASSRF/blob/main/Rps_Http-IOC.ps1
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition:
      all of ($s*)
      and not 1 of ($fp*)
}

rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_3 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22"
      score = 60
   strings:
      $sa1 = " POST /powershell - 444 " ascii wide
      $sa2 = " POST /Powershell - 444 " ascii wide
      $sb1 = " - 200 0 0 2" ascii wide
      
      // based on filters found in CrowdStrikes script https://github.com/CrowdStrike/OWASSRF/blob/main/Rps_Http-IOC.ps1
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition:
      1 of ($sa*) and $sb1 and not 1 of ($fp*)
}

rule EXPL_LOG_ProxyNotShell_PowerShell_Proxy_Log_Dec22_1 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22"
      score = 70
   strings:
      $s1 = ",/Powershell" ascii wide nocase
      $s2 = ",Kerberos,true," ascii wide
      $s3 = ",200,0,,,," ascii wide
      $sx1 = ";OnEndRequest.End.ContentType=application/soap+xml charset UTF-8;S:ServiceCommonMetadata.HttpMethod=POST;"

      // based on filters found in CrowdStrikes script https://github.com/CrowdStrike/OWASSRF/blob/main/Rps_Http-IOC.ps1
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition:
      all of ($s*)
      and not 1 of ($fp*)
}

