
rule SUSP_PS1_Msdt_Execution_May22 {
   meta:
      description = "Detects suspicious calls of msdt.exe as seen in CVE-2022-30190 / Follina exploitation"
      author = "Nasreddine Bencherchali, Christian Burkard"
      date = "2022-05-31"
      modified = "2025-03-21"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 65
   strings:
      $a = "PCWDiagnostic" ascii wide fullword
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt" ascii wide

      $sb1 = "/af " ascii wide
      $sb2 = "-af " ascii wide
      $sb3 = "IT_BrowseForFile=" ascii wide

      /* OriginalFilename pcwrun.exe */
      $fp1 = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00
               46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00
               00 00 70 00 63 00 77 00 72 00 75 00 6E 00 2E 00
               65 00 78 00 65 00 }
      $fp2 = "FilesFullTrust" wide
      $fp3 = "Cisco Spark" ascii wide
      $fp4 = "author: " ascii
   condition:
      filesize < 10MB
      and $a
      and 1 of ($sa*)
      and 1 of ($sb*)
      and not 1 of ($fp*)
      // not JSON
      and not uint8(0) == 0x7B
}

rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
      date = "2022-05-30"
      modified = "2022-06-20"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
      id = "304c4816-b2f6-5319-9fe9-8f74bdb82ad0"
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii

      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii
      $x3 = "%2E%68%74%6D%6C%21" ascii /* encoded version of .html! */
      $x4 = "%2E%68%74%6D%21" ascii /* encoded version of .htm! */
   condition:
      filesize < 50KB
      and all of ($a*)
      and 1 of ($x*)
}

rule SUSP_Doc_RTF_ExternalResource_May22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-05-31"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
      id = "71bb97e0-ec12-504c-a1f6-25039ac91c86"
   strings:
      $s1 = " LINK htmlfile \"http" ascii
      $s2 = ".html!\" " ascii
   condition:
      uint32be(0) == 0x7B5C7274 and
      filesize < 300KB and
      all of them
}

rule EXPL_Follina_CVE_2022_30190_Msdt_MSProtocolURI_May22 {
   meta:
      description = "Detects the malicious usage of the ms-msdt URI as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard"
      date = "2022-05-30"
      modified = "2022-07-18"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash1 = "4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784"
      hash2 = "778cbb0ee4afffca6a0b788a97bc2f4855ceb69ddc5eaa230acfa2834e1aeb07"
      score = 80
      id = "62e67c25-a420-5dac-9d1c-b0648ea6b574"
   strings:
      $re1 = /location\.href\s{0,20}=\s{0,20}"ms-msdt:/
      $a1 = "%6D%73%2D%6D%73%64%74%3A%2F" ascii /* URL encoded "ms-msdt:/" */
   condition:
      filesize > 3KB and
      filesize < 100KB and
      1 of them
}

rule SUSP_Doc_RTF_OLE2Link_Jun22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources"
      author = "Christian Burkard"
      date = "2022-06-01"
      reference = "Internal Research"
      hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
      score = 75
      id = "e9c83d58-6214-51d5-882a-4bd2ed6acc9a"
   strings:
      $sa = "\\objdata" ascii nocase

      $sb1 = "4f4c45324c696e6b" ascii /* OLE2Link */
      $sb2 = "4F4C45324C696E6B" ascii

      $sc1 = "d0cf11e0a1b11ae1" ascii /* docfile magic - doc file albilae */
      $sc2 = "D0CF11E0A1B11AE1" ascii

      $x1 = "68007400740070003a002f002f00" ascii /* http:// */
      $x2 = "68007400740070003A002F002F00" ascii
      $x3 = "680074007400700073003a002f002f00" ascii /* https:// */
      $x4 = "680074007400700073003A002F002F00" ascii
      $x5 = "6600740070003a002f002f00" ascii /* ftp:// */
      $x6 = "6600740070003A002F002F00" ascii
      /* TODO: more protocols */
   condition:
      ( uint32be(0) == 0x7B5C7274 or uint32be(0) == 0x7B5C2A5C ) /* RTF */
      and $sa
      and 1 of ($sb*)
      and 1 of ($sc*)
      and 1 of ($x*)
}

rule SUSP_Doc_RTF_OLE2Link_EMAIL_Jun22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources inside e-mail attachments"
      author = "Christian Burkard"
      date = "2022-06-01"
      reference = "Internal Research"
      hash = "4abc20e5130b59639e20bd6b8ad759af18eb284f46e99a5cc6b4f16f09456a68"
      score = 75
      id = "48cde505-3ce4-52ef-b338-0c08ac4f63de"
   strings:
      /* \objdata" */
      $sa1 = "XG9iamRhdG" ascii
      $sa2 = "xvYmpkYXRh" ascii
      $sa3 = "cb2JqZGF0Y" ascii

      /* OLE2Link */
      $sb1 = "NGY0YzQ1MzI0YzY5NmU2Y" ascii
      $sb2 = "RmNGM0NTMyNGM2OTZlNm" ascii
      $sb3 = "0ZjRjNDUzMjRjNjk2ZTZi" ascii
      $sb4 = "NEY0QzQ1MzI0QzY5NkU2Q" ascii
      $sb5 = "RGNEM0NTMyNEM2OTZFNk" ascii
      $sb6 = "0RjRDNDUzMjRDNjk2RTZC" ascii

      /* docfile magic - doc file albilae */
      $sc1 = "ZDBjZjExZTBhMWIxMWFlM" ascii
      $sc2 = "QwY2YxMWUwYTFiMTFhZT" ascii
      $sc3 = "kMGNmMTFlMGExYjExYWUx" ascii
      $sc4 = "RDBDRjExRTBBMUIxMUFFM" ascii
      $sc5 = "QwQ0YxMUUwQTFCMTFBRT" ascii
      $sc6 = "EMENGMTFFMEExQjExQUUx" ascii

      /* http:// */
      $x1 = "NjgwMDc0MDA3NDAwNzAwMDNhMDAyZjAwMmYwM" ascii
      $x2 = "Y4MDA3NDAwNzQwMDcwMDAzYTAwMmYwMDJmMD" ascii
      $x3 = "2ODAwNzQwMDc0MDA3MDAwM2EwMDJmMDAyZjAw" ascii
      $x4 = "NjgwMDc0MDA3NDAwNzAwMDNBMDAyRjAwMkYwM" ascii
      $x5 = "Y4MDA3NDAwNzQwMDcwMDAzQTAwMkYwMDJGMD" ascii
      $x6 = "2ODAwNzQwMDc0MDA3MDAwM0EwMDJGMDAyRjAw" ascii
      /* https:// */
      $x7 = "NjgwMDc0MDA3NDAwNzAwMDczMDAzYTAwMmYwMDJmMD" ascii
      $x8 = "Y4MDA3NDAwNzQwMDcwMDA3MzAwM2EwMDJmMDAyZjAw" ascii
      $x9 = "2ODAwNzQwMDc0MDA3MDAwNzMwMDNhMDAyZjAwMmYwM" ascii
      $x10 = "NjgwMDc0MDA3NDAwNzAwMDczMDAzQTAwMkYwMDJGMD" ascii
      $x11 = "Y4MDA3NDAwNzQwMDcwMDA3MzAwM0EwMDJGMDAyRjAw" ascii
      $x12 = "2ODAwNzQwMDc0MDA3MDAwNzMwMDNBMDAyRjAwMkYwM" ascii
      /* ftp:// */
      $x13 = "NjYwMDc0MDA3MDAwM2EwMDJmMDAyZjAw" ascii
      $x14 = "Y2MDA3NDAwNzAwMDNhMDAyZjAwMmYwM" ascii
      $x15 = "2NjAwNzQwMDcwMDAzYTAwMmYwMDJmMD" ascii
      $x16 = "NjYwMDc0MDA3MDAwM0EwMDJGMDAyRjAw" ascii
      $x17 = "Y2MDA3NDAwNzAwMDNBMDAyRjAwMkYwM" ascii
      $x18 = "2NjAwNzQwMDcwMDAzQTAwMkYwMDJGMD" ascii
      /* TODO: more protocols */
   condition:
      filesize < 10MB
      and 1 of ($sa*)
      and 1 of ($sb*)
      and 1 of ($sc*)
      and 1 of ($x*)
}

rule SUSP_DOC_RTF_ExternalResource_EMAIL_Jun22 {
   meta:
      description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation inside e-mail attachment"
      author = "Christian Burkard"
      date = "2022-06-01"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      score = 70
      id = "3ddc838c-8520-5572-9652-8cb823f83e27"
   strings:
      /* <Relationships */
      $sa1 ="PFJlbGF0aW9uc2hpcH" ascii
      $sa2 ="xSZWxhdGlvbnNoaXBz" ascii
      $sa3 ="8UmVsYXRpb25zaGlwc" ascii
      /* TargetMode="External" */
      $sb1 ="VGFyZ2V0TW9kZT0iRXh0ZXJuYWwi" ascii
      $sb2 ="RhcmdldE1vZGU9IkV4dGVybmFsI" ascii
      $sb3 ="UYXJnZXRNb2RlPSJFeHRlcm5hbC" ascii
      /* .html!" */
      $sc1 ="Lmh0bWwhI" ascii
      $sc2 ="5odG1sIS" ascii
      $sc3 ="uaHRtbCEi" ascii
   condition:
      filesize < 400KB
      and 1 of ($sa*)
      and 1 of ($sb*)
      and 1 of ($sc*)
}

rule SUSP_Msdt_Artefact_Jun22_2 {
   meta:
      description = "Detects suspicious pattern in msdt diagnostics log (e.g. CVE-2022-30190 / Follina exploitation)"
      author = "Christian Burkard"
      date = "2022-06-01"
      modified = "2022-07-29"
      reference = "https://twitter.com/nas_bench/status/1531718490494844928"
      score = 75
      id = "aa2a4bd7-2094-5652-a088-f58d0c7d3f62"
   strings:
      $a1 = "<ScriptError><Data id=\"ScriptName\" name=\"Script\">TS_ProgramCompatibilityWizard.ps1" ascii

      $x1 = "/../../" ascii
      $x2 = "$(Invoke-Expression" ascii
      $x3 = "$(IEX(" ascii nocase
   condition:
      uint32(0) == 0x6D783F3C /* <?xm */
      and $a1
      and 1 of ($x*)
}

rule SUSP_LNK_Follina_Jun22 {
   meta:
      description = "Detects LNK files with suspicious Follina/CVE-2022-30190 strings"
      author = "Paul Hager"
      date = "2022-06-02"
      reference = "https://twitter.com/gossithedog/status/1531650897905950727"
      score = 75
      id = "d331d584-2ab3-5275-b435-6129c7291417"
   strings:
      $sa1 = "msdt.exe" ascii wide
      $sa2 = "msdt " ascii wide
      $sa3 = "ms-msdt:" ascii wide

      $sb = "IT_BrowseForFile=" ascii wide
   condition:
      filesize < 5KB and
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and
      1 of ($sa*) and $sb
}
