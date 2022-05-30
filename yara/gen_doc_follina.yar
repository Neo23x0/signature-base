rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
   strings:
      $a1 = "<Relationships" ascii
      $x1 = ".html!\" TargetMode=\"External\"" ascii
   condition:
      filesize < 50KB and
      all of them
}

rule SUSP_Doc_RTF_externalResource_May22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which download external resources"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
   strings:
      $s1 = " LINK htmlfile \"http" ascii
      $s2 = ".html!\" " ascii
   condition:
      filesize < 300KB and
      uint32be(0) == 0x7B5C7274 and
      all of them
}
