
rule WEBSHELL_ASP_Embedded_Mar21_1 {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-05"
      score = 85
      id = "7cf7db9d-8f8a-51db-a0e6-84748e8f9e1f"
   strings:
      $s1 = "<script runat=\"server\">" nocase
      $s2 = "new System.IO.StreamWriter(Request.Form["
      $s3 = ".Write(Request.Form["
   condition:
      filesize < 100KB and all of them
}

rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1 {
   meta:
      description = "Detects HAFNIUM SecChecker webshell"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/markus_neis/status/1367794681237667840"
      date = "2021-03-05"
      hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
      id = "73db3d78-7ece-53be-9efb-d19801993d5e"
   strings:
      $x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
      $x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword
   condition:
      uint16(0) == 0x253c and
      filesize < 1KB and
      1 of them or 2 of them
}

rule APT_HAFNIUM_Forensic_Artefacts_Mar21_1 {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-02"
      id = "872822b0-34d9-5ae4-a532-6a8786494fa9"
   strings:
      $s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
      $s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
      $s3 = "powercat.ps1'); powercat -c" ascii wide fullword
   condition:
      1 of them
}

rule APT_WEBSHELL_HAFNIUM_Chopper_WebShell: APT Hafnium WebShell {
   meta:
      description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
      author = "Markus Neis,Swisscom"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "25dcf166-4aea-5680-b161-c5fc8d74b987"
   strings:
      $x1 = "runat=\"server\">" nocase

      $s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request" nocase
      $s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
      $s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\"" nocase  
   condition:
      filesize < 10KB and $x1 and 1 of ($s*) 
}

rule APT_WEBSHELL_Tiny_WebShell : APT Hafnium WebShell {
   meta:
      description = "Detects WebShell Injection"
      author = "Markus Neis,Swisscom"
      hash = "099c8625c58b315b6c11f5baeb859f4c"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "aa2fcecc-4c8b-570d-a81a-5dfb16c04e05"
   strings:
      $x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"

      $s1 = "=Request.Form(\""
      $s2 = "eval("
   condition:
      filesize < 300 and all of ($s*) and $x1
} 

rule HKTL_PS1_PowerCat_Mar21 {
   meta:
      description = "Detects PowerCat hacktool"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/besimorhino/powercat"
      date = "2021-03-02"
      hash1 = "c55672b5d2963969abe045fe75db52069d0300691d4f1f5923afeadf5353b9d2"
      id = "ae3963e8-2fe9-5bc3-bf72-95f136622832"
   strings:
      $x1 = "powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com" ascii fullword
      $x2 = "try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}" ascii fullword

      $s1 = "Returning Encoded Payload..." ascii
      $s2 = "$CommandToExecute =" ascii fullword
      $s3 = "[alias(\"Execute\")][string]$e=\"\"," ascii
   condition:
      uint16(0) == 0x7566 and
      filesize < 200KB and
      1 of ($x*) or 3 of them
}

rule HKTL_Nishang_PS1_Invoke_PowerShellTcpOneLine {
   meta:
      description = "Detects PowerShell Oneliner in Nishang's repository"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
      date = "2021-03-03"
      hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"
      id = "0218ebbd-2dbe-5838-ab53-1e78e3f97b9e"
   strings:
      $s1 = "=([text.encoding]::ASCII).GetBytes((iex $" ascii wide
      $s2 = ".GetStream();[byte[]]$" ascii wide
      $s3 = "New-Object Net.Sockets.TCPClient('" ascii wide
   condition:
      all of them
}

rule WEBSHELL_ASPX_SimpleSeeSharp : Webshell Unclassified {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
      hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "469fdf5c-e09e-5d44-a2e6-0864dcd0e18a"
   strings:
      $header = "<%@ Page Language=\"C#\" %>"
      $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"
   condition:
      $header at 0 and
      $body and
      filesize < 1KB
}

rule WEBSHELL_ASPX_reGeorgTunnel : Webshell Commodity {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "variation on reGeorgtunnel"
      hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
      reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
      id = "b8aa27c9-a28a-5051-8f81-1184f28842ed"
   strings:
      $s1 = "System.Net.Sockets"
      $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
      $t1 = ".Split('|')"
      $t2 = "Request.Headers.Get"
      $t3 = ".Substring("
      $t4 = "new Socket("
      $t5 = "IPAddress ip;"
   condition:
      all of ($s*) or
      all of ($t*)
}

rule WEBSHELL_ASPX_SportsBall {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
      hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      id = "25b23a4c-8fc7-5d6f-b4b5-46fe2c1546d8"
   strings:
      $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
      $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="

      $var1 = "Result.InnerText = string.Empty;"
      $var2 = "newcook.Expires = DateTime.Now.AddDays("
      $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
      $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
      $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
      $var6 = "<input type=\"submit\" value=\"Upload\" />"
   condition:
      any of ($uniq*) or
      all of ($var*)
}

rule WEBSHELL_CVE_2021_27065_Webshells {
   meta:
      description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
      author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
      date = "2021-03-05"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      id = "27677f35-24a3-59cc-a3ad-b83884128da7"
   strings:
      $script1 = "script language" ascii wide nocase
      $script2 = "page language" ascii wide nocase
      $script3 = "runat=\"server\"" ascii wide nocase
      $script4 = "/script" ascii wide nocase
      $externalurl = "externalurl" ascii wide nocase
      $internalurl = "internalurl" ascii wide nocase
      $internalauthenticationmethods = "internalauthenticationmethods" ascii wide nocase
      $extendedprotectiontokenchecking = "extendedprotectiontokenchecking" ascii wide nocase
   condition:
      filesize < 50KB and any of ($script*) and ($externalurl or $internalurl) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3 {
   meta:
      description = "Detects HAFNIUM ASPX files dropped on compromised servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-07"
      score = 85
      id = "9c2ba123-63c4-5e9c-a08f-bd9db3304691"
   strings:
      $s1 = "runat=\"server\">void Page_Load(object" ascii wide 
      $s2 = "Request.Files[0].SaveAs(Server.MapPath(" ascii wide
   condition:
      filesize < 50KB and
      all of them
}

rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4 {
   meta:
      description = "Detects HAFNIUM ASPX files dropped on compromised servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-07"
      score = 85
      id = "93f5b682-642d-5edf-84a9-296bf12cd72b"
   strings:
      $s1 = "<%@Page Language=\"Jscript\"%>" ascii wide nocase
      $s2 = ".FromBase64String(" ascii wide nocase
      $s3 = "eval(System.Text.Encoding." ascii wide nocase
   condition:
      filesize < 850 and
      all of them
}

rule APT_HAFNIUM_ForensicArtefacts_WER_Mar21_1 {
   meta:
      description = "Detects a Windows Error Report (WER) that indicates and exploitation attempt of the Exchange server as described in CVE-2021-26857 after the corresponding patches have been applied. WER files won't be written upon successful exploitation before applying the patch. Therefore, this indicates an unsuccessful attempt."
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1368471533048446976"
      date = "2021-03-07"
      score = 40
      id = "06771101-10ce-5d6b-99f7-a321aade7f69"
   strings:
      $s1 = "AppPath=c:\\windows\\system32\\inetsrv\\w3wp.exe" wide fullword
      $s7 = ".Value=w3wp#MSExchangeECPAppPool" wide
   condition:
      uint16(0) == 0xfeff and
      filesize < 8KB and
      all of them
}

rule APT_HAFNIUM_ForensicArtefacts_Cab_Recon_Mar21_1 {
   meta:
      description = "Detects suspicious CAB files used by HAFNIUM for recon activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3?u=dstepanic"
      date = "2021-03-11"
      score = 70
      id = "b0caf9d9-af0a-5181-85e4-6091cd6699e3"
   strings:
      $s1 = "ip.txt" ascii fullword
      $s2 = "arp.txt" ascii fullword
      $s3 = "system" ascii fullword 
      $s4 = "security" ascii fullword
   condition:
      uint32(0) == 0x4643534d and
      filesize < 10000KB and (
         $s1 in (0..200) and 
         $s2 in (0..200) and
         $s3 in (0..200) and
         $s4 in (0..200)
      )
}

rule WEBSHELL_Compiled_Webshell_Mar2021_1 {
   meta:
      description = "Triggers on temporary pe files containing strings commonly used in webshells."
      author = "Bundesamt fuer Sicherheit in der Informationstechnik"
      date = "2021-03-05"
      modified = "2021-03-12"
      reference = "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/Vorfaelle/Exchange-Schwachstellen-2021/MSExchange_Schwachstelle_Detektion_Reaktion.pdf"
      id = "9336bd2c-791c-5c3e-9733-724a6a23864a"
   strings:
      $x1 = /App_Web_[a-zA-Z0-9]{7,8}.dll/ ascii wide fullword
      $a1 = "~/aspnet_client/" ascii wide nocase
      $a2 = "~/auth/" ascii wide nocase
      $b1 = "JScriptEvaluate" ascii wide fullword
      $c1 = "get_Request" ascii wide fullword
      $c2 = "get_Files" ascii wide fullword
      $c3 = "get_Count" ascii wide fullword
      $c4 = "get_Item" ascii wide fullword
      $c5 = "get_Server" ascii wide fullword
   condition:
      uint16(0) == 0x5a4d and filesize > 5KB and filesize < 40KB and all of ($x*) and 1 of ($a*) and ( all of ($b*) or all of ($c*) )
}

rule APT_MAL_ASP_DLL_HAFNIUM_Mar21_1 {
   meta:
      description = "Detects HAFNIUM compiled ASP.NET DLLs dropped on compromised servers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-05"
      score = 65
      hash1 = "097f5f700c000a13b91855beb61a931d34fb0abb738a110368f525e25c5bc738"
      hash2 = "15744e767cbaa9b37ff7bb5c036dda9b653fc54fc9a96fe73fbd639150b3daa3"
      hash3 = "52ae4de2e3f0ef7fe27c699cb60d41129a3acd4a62be60accc85d88c296e1ddb"
      hash4 = "5f0480035ee23a12302c88be10e54bf3adbcf271a4bb1106d4975a28234d3af8"
      hash5 = "6243fd2826c528ee329599153355fd00153dee611ca33ec17effcf00205a6e4e"
      hash6 = "ebf6799bb86f0da2b05e66a0fe5a9b42df6dac848f4b951b2ed7b7a4866f19ef"
      id = "68b8252e-a07d-5507-b556-a4d473f98157"
   strings:
      $s1 = "Page_Load" ascii fullword
      
      $sc1 = { 20 00 3A 00 20 00 68 00 74 00 74 00 70 00 3A 00
               2F 00 2F 00 (66|67) 00 2F 00 00 89 A3 0D 00 0A 00 }

      $op1 = { 00 43 00 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f }
      $op2 = { 58 00 77 00 30 00 4a 00 45 00 00 51 7e 00 2f 00 61 00 }
      $op3 = { 01 0e 0e 05 20 01 01 11 79 04 07 01 12 2d 04 07 01 12 31 02 }
      $op4 = { 5e 00 03 00 bc 22 00 00 00 00 01 00 85 03 2b 00 03 00 cc }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 50KB and
      all of ($s*) or all of ($op*)
}


rule WEBSHELL_HAFNIUM_CISA_10328929_01 : trojan webshell exploit CVE_2021_27065 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-03-17"
       description = "Detects CVE-2021-27065 Webshellz"
       hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
       reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
       id = "81916396-8aaa-5045-b31c-4bcce8d295a5"
   strings:
       $s0 = { 65 76 61 6C 28 52 65 71 75 65 73 74 5B 22 [1-32] 5D 2C 22 75 6E 73 61 66 65 22 29 }
       $s1 = { 65 76 61 6C 28 }
       $s2 = { 28 52 65 71 75 65 73 74 2E 49 74 65 6D 5B [1-36] 5D 29 29 2C 22 75 6E 73 61 66 65 22 29 }
       $s3 = { 49 4F 2E 53 74 72 65 61 6D 57 72 69 74 65 72 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
       $s4 = { 57 72 69 74 65 28 52 65 71 75 65 73 74 2E 46 6F 72 6D 5B [1-24] 5D }
   condition:
       $s0 or ($s1 and $s2) or ($s3 and $s4)
}

rule WEBSHELL_HAFNIUM_CISA_10328929_02 : trojan webshell exploit CVE_2021_27065 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-03-17"
       description = "Detects CVE-2021-27065 Exchange OAB VD MOD"
       hash = "c8a7b5ffcf23c7a334bb093dda19635ec06ca81f6196325bb2d811716c90f3c5"
       reference = "https://us-cert.cisa.gov/ncas/analysis-reports/ar21-084a"
       id = "34a89a6e-fa8a-5c64-a325-30202e20b30f"
   strings:
       $s0 = { 4F 66 66 6C 69 6E 65 41 64 64 72 65 73 73 42 6F 6F 6B 73 }
       $s1 = { 3A 20 68 74 74 70 3A 2F 2F [1] 2F }
       $s2 = { 45 78 74 65 72 6E 61 6C 55 72 6C 20 20 20 20 }
   condition:
       $s0 and $s1 and $s2
}


rule WEBSHELL_ASPX_FileExplorer_Mar21_1 {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-31"
      score = 80
      hash1 = "a8c63c418609c1c291b3e731ca85ded4b3e0fba83f3489c21a3199173b176a75"
      id = "edcaa2a8-6fea-584e-90c2-307a2dfc9f7f"
   strings:
      $x1 = "<span style=\"background-color: #778899; color: #fff; padding: 5px; cursor: pointer\" onclick=" ascii
      $xc1 = { 3C 61 73 70 3A 48 69 64 64 65 6E 46 69 65 6C 64
               20 72 75 6E 61 74 3D 22 73 65 72 76 65 72 22 20
               49 44 3D 22 ?? ?? ?? ?? ?? 22 20 2F 3E 3C 62 72
               20 2F 3E 3C 62 72 20 2F 3E 20 50 72 6F 63 65 73
               73 20 4E 61 6D 65 3A 3C 61 73 70 3A 54 65 78 74
               42 6F 78 20 49 44 3D } 
      $xc2 = { 22 3E 43 6F 6D 6D 61 6E 64 3C 2F 6C 61 62 65 6C
               3E 3C 69 6E 70 75 74 20 69 64 3D 22 ?? ?? ?? ??
               ?? 22 20 74 79 70 65 3D 22 72 61 64 69 6F 22 20
               6E 61 6D 65 3D 22 74 61 62 73 22 3E 3C 6C 61 62
               65 6C 20 66 6F 72 3D 22 ?? ?? ?? ?? ?? 22 3E 46
               69 6C 65 20 45 78 70 6C 6F 72 65 72 3C 2F 6C 61
               62 65 6C 3E 3C 25 2D 2D }

      $r1 = "(Request.Form[" ascii
      $s1 = ".Text + \" Created!\";" ascii
      $s2 = "DriveInfo.GetDrives()" ascii
      $s3 = "Encoding.UTF8.GetString(FromBase64String(str.Replace(" ascii
      $s4 = "encodeURIComponent(btoa(String.fromCharCode.apply(null, new Uint8Array(bytes))));;"
   condition:
      uint16(0) == 0x253c and
      filesize < 100KB and
      ( 1 of ($x*) or 2 of them ) or 4 of them
}

rule WEBSHELL_ASPX_Chopper_Like_Mar21_1 {
   meta:
      description = "Detects Chopper like ASPX Webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-03-31"
      score = 85
      hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
      id = "a4dc1880-865f-5e20-89a2-3a642c453ef9"
   strings:
      $s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
      $s2 = "));function Page_Load(){var _0x" ascii
      $s3 = ";eval(Request[_0x" ascii
      $s4 = "','orange','unsafe','" ascii
   condition:
      filesize < 3KB and
      1 of them or 2 of them
}
