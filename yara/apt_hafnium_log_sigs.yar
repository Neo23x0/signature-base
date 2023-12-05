
rule EXPL_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-02"
      id = "dcc1f741-cab0-5a0b-a261-a6bd05989723"
   strings:
      $s1 = "S:CMD=Set-OabVirtualDirectory.ExternalUrl='" ascii wide fullword
   condition:
      1 of them
}

rule EXPL_LOG_CVE_2021_26858_Exchange_Forensic_Artefacts_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-26858"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-02"
      score = 65
      modified = "2021-03-04"
      id = "f6fa90c7-c2c0-56db-bf7b-dc146761a995"
   strings:
      $xr1 = /POST (\/owa\/auth\/Current\/themes\/resources\/logon\.css|\/owa\/auth\/Current\/themes\/resources\/owafont_ja\.css|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif|\/owa\/auth\/Current\/themes\/resources\/owafont_ko\.css|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiBold\.eot|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiLight\.ttf|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif)/   
   condition:
      $xr1
}

rule LOG_APT_HAFNIUM_Exchange_Log_Traces_Mar21_1 : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
      date = "2021-03-04"
      score = 65
      id = "a51f0bd5-c6fd-5ee4-9d30-9a6001778013"
   strings:
      $xr1 = /POST \/(ecp\/y\.js|ecp\/main\.css|ecp\/default\.flt|ecp\/auth\/w\.js|owa\/auth\/w\.js)[^\n]{100,600} (200|301|302) /

      $xr3 = /POST \/owa\/auth\/Current\/[^\n]{100,600} (DuckDuckBot\/1\.0;\+\(\+http:\/\/duckduckgo\.com\/duckduckbot\.html\)|facebookexternalhit\/1\.1\+\(\+http:\/\/www\.facebook\.com\/externalhit_uatext\.php\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\)|Mozilla\/5\.0\+\(compatible;\+Bingbot\/2\.0;\+\+http:\/\/www\.bing\.com\/bingbot\.htm\)|Mozilla\/5\.0\+\(compatible;\+Googlebot\/2\.1;\+\+http:\/\/www\.google\.com\/bot\.html|Mozilla\/5\.0\+\(compatible;\+Konqueror\/3\.5;\+Linux\)\+KHTML\/3\.5\.5\+\(like\+Gecko\)\+\(Exabot-Thumbnails\)|Mozilla\/5\.0\+\(compatible;\+Yahoo!\+Slurp;\+http:\/\/help\.yahoo\.com\/help\/us\/ysearch\/slurp\)|Mozilla\/5\.0\+\(compatible;\+YandexBot\/3\.0;\+\+http:\/\/yandex\.com\/bots\)|Mozilla\/5\.0\+\(X11;\+Linux\+x86_64\)\+AppleWebKit\/537\.36\+\(KHTML,\+like\+Gecko\)\+Chrome\/51\.0\.2704\.103\+Safari\/537\.3)/
      $xr4 = /POST \/ecp\/[^\n]{100,600} (ExchangeServicesClient\/0\.0\.0\.0|python-requests\/2\.19\.1|python-requests\/2\.25\.1)[^\n]{200,600} (200|301|302) /
      $xr5 = /POST \/(aspnet_client|owa)\/[^\n]{100,600} (antSword\/v2\.1|Googlebot\/2\.1\+\(\+http:\/\/www\.googlebot\.com\/bot\.html\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\))[^\n]{200,600} (200|301|302) /
   condition:
      1 of them
}

rule LOG_Exchange_Forensic_Artefacts_CleanUp_Activity_Mar21_1 : LOG {
   meta:
      description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
      date = "2021-03-08"
      score = 70
      id = "95b19544-147b-5496-b717-669cbc488179"
   strings:
      $x1 = "cmd.exe /c cd /d C:/inetpub/wwwroot/aspnet_client" ascii wide
      $x2 = "cmd.exe /c cd /d C:\\inetpub\\wwwroot\\aspnet_client" ascii wide
      
      $s1 = "aspnet_client&del '"
      $s2 = "aspnet_client&attrib +h +s +r "
      $s3 = "&echo [S]"
   condition:
      1 of ($x*) or 2 of them
}

rule EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Zach Stanford - @svch0st, Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/#scan-log"
      reference_2 = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
      date = "2021-03-10"
      modified = "2021-03-15"
      score = 65
      id = "8b0110a9-fd03-5f7d-bdd8-03ff48bcac68"
   strings:
      $x1 = "ServerInfo~" ascii wide

      $sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide  /* Adjusted to cover MSF exploit https://github.com/rapid7/metasploit-framework/blob/e5c76bfe13acddc4220d7735fdc3434d9c64736e/modules/exploits/windows/http/exchange_proxylogon_rce.rb */

      $s1 = "/ecp/auth/w.js" ascii wide 
      $s2 = "/owa/auth/w.js" ascii wide
      $s3 = "/owa/auth/x.js" ascii wide
      $s4 = "/ecp/main.css" ascii wide
      $s5 = "/ecp/default.flt" ascii wide
      $s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide
   condition:
      $x1 and 1 of ($s*)
}

rule LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_2 : LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
      date = "2021-03-10"
      score = 65
      id = "37a26def-b360-518e-a4ab-9604a5b39afd"
   strings:
      $sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/
   condition:
      $sr1
}
