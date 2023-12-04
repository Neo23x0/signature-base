
rule EXPL_Exchange_ProxyShell_Failed_Aug21_1 : SCRIPT {
   meta:
      description = "Detects ProxyShell exploitation attempts in log files"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08"
      modified = "2021-08-09"
   strings:
      $xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-Rps-CAT)[^\n]{1,400}401 0 0/ nocase ascii
      $xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}401 0 0/ nocase ascii
   condition:
      1 of them
}

rule EXPL_Exchange_ProxyShell_Successful_Aug21_1 : SCRIPT {
   meta:
      description = "Detects successful ProxyShell exploitation attempts in log files"
      author = "Florian Roth (Nextron Systems)"
      score = 85
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08"
      modified = "2021-08-09"
   strings:
      $xr1a = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|X-Rps-CAT)/ nocase ascii
      $xr1b = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(mapi\/nspi|EWS\/)[^\n]{1,400}(200|302) 0 0/ 
      $xr2 = /autodiscover\/autodiscover\.json[^\n]{1,60}&X-Rps-CAT=/ nocase ascii
      $xr3 = /Email=autodiscover\/autodiscover\.json[^\n]{1,400}200 0 0/ nocase ascii
   condition:
      1 of them
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_2 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST), size and content"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-exchange-servers-are-getting-hacked-via-proxyshell-exploits/"
      date = "2021-08-13"
   strings:
      $s1 = "Page Language=" ascii nocase
   condition:
      uint32(0) == 0x4e444221 /* PST header: !BDN */
      and filesize < 2MB
      and $s1
}

rule WEBSHELL_ASPX_ProxyShell_Aug21_3 {
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be DER), size and content"
      author = "Max Altgelt"
      reference = "https://twitter.com/gossithedog/status/1429175908905127938?s=12"
      date = "2021-08-23"
      score = 75
   strings:
      $s1 = "Page Language=" ascii nocase
   condition:
      uint16(0) == 0x8230 /* DER start */
      and filesize < 10KB
      and $s1
}

rule WEBSHELL_ASPX_ProxyShell_Sep21_1 { 
   meta:
      description = "Detects webshells dropped by ProxyShell exploitation based on their file header (must be PST) and base64 decoded request"
      author = "Tobias Michalski"
      date = "2021-09-17"
      reference = "Internal Research"
      hash = "219468c10d2b9d61a8ae70dc8b6d2824ca8fbe4e53bbd925eeca270fef0fd640"
      score = 75
   strings:
      $s = ".FromBase64String(Request["
   condition:
      uint32(0) == 0x4e444221
      and any of them
}

rule APT_IIS_Config_ProxyShell_Artifacts {
   meta:
      description = "Detects virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
      date = "2021-08-25"
      score = 90
   strings:
      $a1 = "<site name=" ascii /* marker used to select IIS configs */
      $a2 = "<sectionGroup name=\"system.webServer\">" ascii

      $sa1 = " physicalPath=\"C:\\ProgramData\\COM" ascii
      $sa2 = " physicalPath=\"C:\\ProgramData\\WHO" ascii
      $sa3 = " physicalPath=\"C:\\ProgramData\\ZING" ascii
      $sa4 = " physicalPath=\"C:\\ProgramData\\ZOO" ascii
      $sa5 = " physicalPath=\"C:\\ProgramData\\XYZ" ascii
      $sa6 = " physicalPath=\"C:\\ProgramData\\AUX" ascii
      $sa7 = " physicalPath=\"C:\\ProgramData\\CON\\" ascii

      $sb1 = " physicalPath=\"C:\\Users\\All Users\\" ascii
   condition:
      filesize < 500KB and all of ($a*) and 1 of ($s*)
}

rule WEBSHELL_ASPX_ProxyShell_Exploitation_Aug21_1 {
   meta:
      description = "Detects unknown malicious loaders noticed in August 2021"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/VirITeXplorer/status/1430206853733097473"
      date = "2021-08-25"
      score = 90
   strings:
      $x1 = ");eval/*asf" ascii
   condition:
      filesize < 600KB and 1 of them
}

rule WEBSHELL_ASPX_ProxyShell_Aug15 {
   meta:
      description = "Webshells iisstart.aspx and Logout.aspx"
      author = "Moritz Oettle"
      reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
      date = "2021-09-04"
      score = 75
   strings:
      $g1 = "language=\"JScript\"" ascii
      $g2 = "function getErrorWord" ascii
      $g3 = "errorWord" ascii
      $g4 = "Response.Redirect" ascii
      $g5 = "function Page_Load" ascii
      $g6 = "runat=\"server\"" ascii
      $g7 = "Request[" ascii
      $g8 = "eval/*" ascii

      $s1 = "AppcacheVer" ascii /* HTTP Request Parameter */
      $s2 = "clientCode" ascii /* HTTP Request Parameter */
      $s3 = "LaTkWfI64XeDAXZS6pU1KrsvLAcGH7AZOQXjrFkT816RnFYJQR" ascii
   condition:
      filesize < 1KB and
      ( 1 of ($s*) or 4 of ($g*) )
}

rule WEBSHELL_Mailbox_Export_PST_ProxyShell_Aug26 {
   meta:
      description = "Webshells generated by an Mailbox export to PST and stored as aspx: 570221043.aspx 689193944.aspx luifdecggoqmansn.aspx"
      author = "Moritz Oettle"
      reference = "https://github.com/hvs-consulting/ioc_signatures/tree/main/Proxyshell"
      date = "2021-09-04"
      score = 85
   strings:
      $x1 = "!BDN" /* PST file header */

      $g1 = "Page language=" ascii
      $g2 = "<%@ Page" ascii
      $g3 = "Request.Item[" ascii
      $g4 = "\"unsafe\");" ascii
      $g5 = "<%eval(" ascii
      $g6 = "script language=" ascii
      $g7 = "Request[" ascii

      $s1 = "gold8899" ascii /* HTTP Request Parameter */
      $s2 = "exec_code" ascii /* HTTP Request Parameter */
      $s3 = "orangenb" ascii /* HTTP Request Parameter */
   condition:
      filesize < 500KB and
      $x1 at 0 and
      ( 1 of ($s*) or 3 of ($g*) )
}


/* 
   Hunting Rules 
*/

rule SUSP_IIS_Config_ProxyShell_Artifacts {
   meta:
      description = "Detects suspicious virtual directory configured in IIS pointing to a ProgramData folder (as found in attacks against Exchange servers in August 2021)"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
      date = "2021-08-25"
      score = 70
   strings:
      $a1 = "<site name=" ascii /* marker used to select IIS configs */
      $a2 = "<sectionGroup name=\"system.webServer\">" ascii

      $s1 = " physicalPath=\"C:\\ProgramData\\" ascii
   condition:
      filesize < 500KB and all of ($a*) and 1 of ($s*)
}

rule SUSP_IIS_Config_VirtualDir {
   meta:
      description = "Detects suspicious virtual directory configured in IIS pointing to a User folder"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit"
      date = "2021-08-25"
      modified = "2022-09-17"
      score = 60
   strings:
      $a1 = "<site name=" ascii /* marker used to select IIS configs */
      $a2 = "<sectionGroup name=\"system.webServer\">" ascii

      $s2 = " physicalPath=\"C:\\Users\\" ascii

      $fp1 = "Microsoft.Web.Administration" wide
      $fp2 = "<virtualDirectory path=\"/\" physicalPath=\"C:\\Users\\admin\\"
   condition:
      filesize < 500KB and all of ($a*) and 1 of ($s*)
      and not 1 of ($fp*)
}

rule SUSP_ASPX_PossibleDropperArtifact_Aug21 {
   meta:
      description = "Detects an ASPX file with a non-ASCII header, often a result of MS Exchange drop techniques"
      reference = "Internal Research"
      author = "Max Altgelt"
      date = "2021-08-23"
      score = 60
   strings:
      $s1 = "Page Language=" ascii nocase

      $fp1 = "Page Language=\"java\"" ascii nocase
   condition:
      filesize < 500KB
      and not uint16(0) == 0x4B50 and not uint16(0) == 0x6152 and not uint16(0) == 0x8b1f // Exclude ZIP / RAR / GZIP files (can cause FPs when uncompressed)
      and not uint16(0) == 0x5A4D // PE
      and not uint16(0) == 0xCFD0 // OLE
      and not uint16(0) == 0xC3D4 // PCAP
      and not uint16(0) == 0x534D // CAB
      and all of ($s*) and not 1 of ($fp*) and
      (
         ((uint8(0) < 0x20 or uint8(0) > 0x7E /*non-ASCII*/ ) and uint8(0) != 0x9 /* tab */ and uint8(0) != 0x0D /* carriage return */ and uint8(0) != 0x0A /* new line */ and uint8(0) != 0xEF /* BOM UTF-8 */)
         or ((uint8(1) < 0x20 or uint8(1) > 0x7E /*non-ASCII*/ ) and uint8(1) != 0x9 /* tab */ and uint8(1) != 0x0D /* carriage return */ and uint8(1) != 0x0A /* new line */ and uint8(1) != 0xBB /* BOM UTF-8 */)
         or ((uint8(2) < 0x20 or uint8(2) > 0x7E /*non-ASCII*/ ) and uint8(2) != 0x9 /* tab */ and uint8(2) != 0x0D /* carriage return */ and uint8(2) != 0x0A /* new line */ and uint8(2) != 0xBF /* BOM UTF-8 */)
         or ((uint8(3) < 0x20 or uint8(3) > 0x7E /*non-ASCII*/ ) and uint8(3) != 0x9 /* tab */ and uint8(3) != 0x0D /* carriage return */ and uint8(3) != 0x0A /* new line */)
         or ((uint8(4) < 0x20 or uint8(4) > 0x7E /*non-ASCII*/ ) and uint8(4) != 0x9 /* tab */ and uint8(4) != 0x0D /* carriage return */ and uint8(4) != 0x0A /* new line */)
         or ((uint8(5) < 0x20 or uint8(5) > 0x7E /*non-ASCII*/ ) and uint8(5) != 0x9 /* tab */ and uint8(5) != 0x0D /* carriage return */ and uint8(5) != 0x0A /* new line */)
         or ((uint8(6) < 0x20 or uint8(6) > 0x7E /*non-ASCII*/ ) and uint8(6) != 0x9 /* tab */ and uint8(6) != 0x0D /* carriage return */ and uint8(6) != 0x0A /* new line */)
         or ((uint8(7) < 0x20 or uint8(7) > 0x7E /*non-ASCII*/ ) and uint8(7) != 0x9 /* tab */ and uint8(7) != 0x0D /* carriage return */ and uint8(7) != 0x0A /* new line */)
      )
}

rule WEBSHELL_ProxyShell_Exploitation_Nov21_1 {
   meta:
      description = "Detects webshells dropped by DropHell malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.deepinstinct.com/blog/do-not-exchange-it-has-a-shell-inside"
      date = "2021-11-01"
      score = 85
   strings:
      $s01 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Request[" ascii wide
      $s02 = "new System.IO.MemoryStream()" ascii wide
      $s03 = "Transform(" ascii wide
   condition:
      all of ($s*)
}
