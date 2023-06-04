
rule WEBSHELL_ASPX_DLL_MOVEit_Jun23_1 {
   meta:
      description = "Detects compiled ASPX web shells found being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.trustedsec.com/blog/critical-vulnerability-in-progress-moveit-transfer-technical-analysis-and-recommendations/?utm_content=251159938&utm_medium=social&utm_source=twitter&hss_channel=tw-403811306"
      date = "2023-06-01"
      score = 85
      hash1 = "6cbf38f5f27e6a3eaf32e2ac73ed02898cbb5961566bb445e3c511906e2da1fa"
   strings:
      $x1 = "human2_aspx" ascii fullword
      $x2 = "X-siLock-Comment" wide
      $x3 = "x-siLock-Step1" wide

      $a1 = "MOVEit.DMZ.Core.Data" ascii fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 40KB and (
         1 of ($x*) and $a1
      ) or all of them
}

rule WEBSHELL_ASPX_MOVEit_Jun23_1 {
   meta:
      description = "Detects ASPX web shells as being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/"
      date = "2023-06-01"
      score = 85
      hash1 = "2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5"
      hash2 = "48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a"
      hash3 = "e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e"
   strings:
      $s1 = "X-siLock-Comment" ascii fullword   
      $s2 = "]; string x = null;" ascii
      $s3 = ";  if (!String.Equals(pass, " ascii
   condition:
      filesize < 150KB and 2 of them
}

rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_1 {
   meta:
      description = "Detects a potential compromise indicator found in MOVEit Transfer logs"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"
      date = "2023-06-01"
      score = 70
   strings:
      $x1 = "POST /moveitisapi/moveitisapi.dll action=m2 " ascii
      $x2 = " GET /human2.aspx - 443 " ascii
   condition:
      1 of them
}

rule LOG_EXPL_MOVEit_Exploitation_Indicator_Jun23_2 {
   meta:
      description = "Detects a potential compromise indicator found in MOVEit Transfer logs"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response"
      date = "2023-06-03"
      score = 70
   strings:
      $a1 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.5195.102+Safari/537.36" ascii
      $a2 = "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/105.0.5195.54+Safari/537.36" ascii
      
      $s1 = " POST /moveitisapi/moveitisapi.dll" ascii
      $s2 = " POST /guestaccess.aspx"
      $s3 = " POST /api/v1/folders/"

      $s4 = "/files uploadType=resumable&"
      $s5 = " action=m2 "
   condition:
      1 of ($a*) and 3 of ($s*)
      or all of ($s*)
}
