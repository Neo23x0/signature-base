rule WEBSHELL_ASPX_Sharepoint_Drop_CVE_2025_53770_Jul25 {
   meta:
      description = "Detects ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      score = 80
      hash = "27c45b8ed7b8a7e5fff473b50c24028bd028a9fe8e25e5cea2bf5e676e531014"
      hash = "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514"
      hash = "b336f936be13b3d01a8544ea3906193608022b40c28dd8f1f281e361c9b64e93"
   strings:
      $x1 = "var sy = System.Reflection.Assembly.Load(" ascii
      $x2 = "Response.Write(cg.ValidationKey+" ascii

      $s1 = "<script runat=\"server\" language=\"c#\" CODEPAGE=\"65001\">" ascii fullword
   condition:
      filesize < 4KB
      and 1 of ($x*)
      or all of them
}

rule WEBSHELL_ASPX_Compiled_Sharepoint_Drop_CVE_2025_53770_Jul25_2 {
   meta:
      description = "Detects compiled ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth, Marius Benthin"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      modified = "2025-07-25"
      score = 75
      hash = "8d3d3f3a17d233bc8562765e61f7314ca7a08130ac0fb153ffd091612920b0f2"
      hash = "d8ca5e5d6400ac34ac4cc138efa89d2ec4d5c0e968a78fa3ba5dbc04c7550649"
      hash = "7e9b77da1f51d03ee2f96bc976f6aeb781f801cf633862a4b8c356cbb555927d"
   strings:
      $x1 = /App_Web_spinstall\d{0,1}.aspx/ wide
      $x2 = /spinstall[\w]?[\._]aspx/ ascii
      $x3 = /\/_layouts\/1[0-9]\/spinstall/ wide
      $x4 = /\/_layouts\/1[0-9]\/ghostfile/ wide

      $s1 = "System.Web.Configuration.MachineKeySection" wide
      $s2 = "Page_load" ascii fullword
      $s3 = "GetApplicationConfig" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 20KB
      and (
         1 of ($x*)
         or all of ($s*)
      )
      or 2 of ($x*)
      or 4 of them
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_1 {
   meta:
      description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      modified = "2025-07-23"
      score = 75
   strings:
      $sa1 = /POST \/_layouts\/1[0-9]\/ToolPane\.aspx/ ascii wide nocase
      $sa2 = "DisplayMode=Edit&a=/ToolPane.aspx" ascii wide

      $sb1 = /GET \/_layouts\/1[0-9]\/spinstall/ ascii wide  // specific
      $sb2 = "/_layouts/SignOut.aspx 200" ascii wide nocase
   condition:
      (@sa2 - @sa1) < 700  // unknown how specific with the DisplayMode=Edit parameter
      or (@sb2 - @sb1) < 700  // specific combination
      or (@sb2 - @sa1) < 700  // most generic combination
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2 {
   meta:
      description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      modified = "2025-07-24"
      hash = "30955794792a7ce045660bb1e1917eef36f1d5865891b8110bf982382b305b27"
      hash = "b336f936be13b3d01a8544ea3906193608022b40c28dd8f1f281e361c9b64e93"
      score = 70
   strings:
      $x1 = "-EncodedCommand JABiAGEAcwBlADYANABTAHQAcgBpAG4AZwAgAD0" ascii wide
      $x2 = "TEMPLATE\\LAYOUTS\\spinstall" ascii wide
      $x3 = "TEMPLATE\\LAYOUTS\\ghostfile" ascii wide
      $x4 = "TEMPLATE\\LAYOUTS\\1.css" ascii wide
      $x5 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:120.0)+Gecko/20100101+Firefox/120.0 /_layouts/SignOut.aspx" ascii wide

      // Encoded code from the dropper (UTF-16 & Base64 encoded)
      // MICROS~1\WEBSER~1\16\TEMPLATE\LAYOUTS\
      // as found in sample f36a11d196db49c80123adf126b78609d0b2f5a0d9850163b6dda27048d17cbc
      $xe1 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA2AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA"
      $xe2 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANgBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA"
      $xe3 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADYAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA"
      // MICROS~1\WEBSER~1\15\TEMPLATE\LAYOUTS\
      $xe4 = "TQBJAEMAUgBPAFMAfgAxAFwAVwBFAEIAUwBFAFIAfgAxAFwAMQA1AFwAVABFAE0AUABMAEEAVABFAFwATABBAFkATwBVAFQAUwBcA"
      $xe5 = "0ASQBDAFIATwBTAH4AMQBcAFcARQBCAFMARQBSAH4AMQBcADEANQBcAFQARQBNAFAATABBAFQARQBcAEwAQQBZAE8AVQBUAFMAXA"
      $xe6 = "NAEkAQwBSAE8AUwB+ADEAXABXAEUAQgBTAEUAUgB+ADEAXAAxADUAXABUAEUATQBQAEwAQQBUAEUAXABMAEEAWQBPAFUAVABTAFwA"
   condition:
      1 of them
}

