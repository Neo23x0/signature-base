
rule APT_CryWiper_Dec22 {
   meta:
      description = "Detects CryWiper malware samples"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist-ru.translate.goog/novyj-troyanec-crywiper/106114/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en"
      date = "2022-12-05"
      score = 75
      id = "d56ccf4e-30ba-5308-ad68-ffc2ae5a1718"
   strings:
      $x1 = "Software\\Sysinternals\\BrowserUpdate"

      $sx1 = "taskkill.exe /f /im MSExchange*"

      $s1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii
      $s2 = "fDenyTSConnections" ascii
   condition:
      1 of ($x*) or all of ($s*)
}
