
rule EXPL_Cleo_Exploitation_Log_Indicators_Dec24 : SCRIPT {
   meta:
      description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
   strings:
      $x1 = "Note: Processing autorun file 'autorun\\health" ascii wide
      $x2 = "60282967-dc91-40ef-a34c-38e992509c2c.xml" ascii wide
      $x3 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " ascii wide
   condition:
      1 of them
}

rule EXPL_Cleo_Exploitation_PS1_Indicators_Dec24 : SCRIPT {
   meta:
      description = "Detects encoded PowerShell loader used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
   strings:
      $xe1 = "Start-Process -WindowStyle Hidden -FilePath jre\\bin\\java.exe" base64 ascii wide
      $xe2 = "$f=\"cleo." base64 ascii wide
      $xe3 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " base64 ascii wide

      $x1 = "$f=\"cleo." ascii wide
      $x2 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " ascii wide
   condition:
      1 of them
}
