rule WEBSHELL_ASPX_Sharepoint_Drop_CVE_2025_53770_Jul25 {
   meta:
      description = "Detects ASPX web shell dropped during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      score = 80
      hash1 = "27c45b8ed7b8a7e5fff473b50c24028bd028a9fe8e25e5cea2bf5e676e531014"
      hash2 = "92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514"
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
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      score = 75
      hash1 = "8d3d3f3a17d233bc8562765e61f7314ca7a08130ac0fb153ffd091612920b0f2"
   strings:
      $x1 = "App_Web_spinstall0.aspx" wide
      $x2 = "spinstall0_aspx" ascii
      $x3 = "/_layouts/15/spinstall0.aspx" wide

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
      score = 70
   strings:
      $sa1 = "POST /_layouts/15/ToolPane.aspx" ascii wide
      $sa2 = "DisplayMode=Edit&a=/ToolPane.aspx" ascii wide

      $sb1 = "GET /_layouts/15/spinstall0.aspx" ascii wide
      $sb2 = "/_layouts/SignOut.aspx 200" ascii wide
   condition:
      (@sa2 - @sa1) < 700
      or (@sb2 - @sb1) < 700
}

rule APT_EXPL_Sharepoint_CVE_2025_53770_ForensicArtefact_Jul25_2 {
   meta:
      description = "Detects URIs accessed during the exploitation of SharePoint RCE vulnerability CVE-2025-53770"
      author = "Florian Roth"
      reference = "https://research.eye.security/sharepoint-under-siege/"
      date = "2025-07-20"
      score = 70
   strings:
      $x1 = "-EncodedCommand JABiAGEAcwBlADYANABTAHQAcgBpAG4AZwAgAD0" ascii wide
      $x2 = "TEMPLATE\\LAYOUTS\\spinstall0.aspx" ascii wide
      $x3 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:120.0)+Gecko/20100101+Firefox/120.0 /_layouts/SignOut.aspx" ascii wide
   condition:
      1 of them
}
