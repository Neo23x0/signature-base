rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieślak"
      date = "2022-05-30"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii
      
      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii   
   condition:
      filesize < 50KB and
      all of ($a*) and 1 of ($x*)
}

rule SUSP_Doc_RTF_ExternalResource_May22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
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
      description = "Detects the malicious usage of the ms-msdt URI"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
      score = 80
   strings:
      $x = "location.href = \"ms-msdt:" ascii
   condition:
      filesize > 3KB and
      filesize < 100KB and
      1 of them
}
