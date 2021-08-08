
rule EXPL_Exchange_ProxyShell_Aug21_1 {
   meta:
      description = "Detects ProxyShell exploitation attempts in log files"
      author = "Florian Roth"
      score = 85
      reference = "https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html"
      date = "2021-08-08"
   strings:
      $xr1 = / \/autodiscover\/autodiscover\.json[^\n]{1,300}\/(powershell|mapi\/nspi|EWS\/|X-RpsCAT)/ nocase ascii
      $xr2 = /autodiscover\/autodiscover\.json[^\n]{1,60}&X-Rps-CAT=/ nocase ascii
      $x1 = "/?&Email=autodiscover/autodiscover.json%3F@" nocase ascii
   condition:
      1 of them
}
