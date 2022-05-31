rule SUSP_PS1_Msdt_Execution_May22 {
   meta:
      description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190"
      author = "Nasreddine Bencherchali, Christian Burkard"
      date = "2022-05-31"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
   strings:
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide

      $sb1 = "ms-msdt:" ascii wide
      $sb2 = "IT_BrowseForFile=" ascii wide
   condition:
      filesize < 10MB
      and 1 of ($sa*)
      and all of ($sb*)
}

rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-05-31"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
   strings:
      $s1 = "<Relationships" ascii
      $s2 = "TargetMode=\"External\"" ascii
      $s3 = ".html!\"" ascii
   condition:
      filesize < 50KB
      and all of them
}

rule SUSP_Doc_RTF_ExternalResource_May22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-05-31"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
   strings:
      $s1 = " LINK htmlfile \"http" ascii
      $s2 = ".html!\" " ascii
   condition:
      uint32be(0) == 0x7B5C7274 and
      filesize < 300KB and
      all of them
}

rule MAL_Msdt_MSProtocolURI_May22 {
   meta:
      description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-05-31"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
      score = 80
   strings:
      $re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
   condition:
      filesize > 3KB and
      filesize < 100KB and
      1 of them
}
