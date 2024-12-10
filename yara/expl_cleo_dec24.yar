
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

rule EXPL_Cleo_Exploitation_XML_Indicators_Dec24 {
   meta:
      description = "Detects XML used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
   strings:
      $x1 = "<Host alias=\"60282967-dc91-40ef-a34c-38e992509c2c\" application=\"\" " ascii
      
      $s1 = "<Commands>SYSTEM cmd.exe /c " ascii
      $a1 = "<Action actiontype=\"Commands\" " ascii
   condition:
      filesize < 50KB and (
         1 of ($x*)
         or 2 of them
      )
}

rule EXPL_Cleo_Exploitation_PS1_Indicators_Dec24 : SCRIPT {
   meta:
      description = "Detects encoded and decoded PowerShell loader used during Cleo software exploitation (as reported by Huntress in December 2024)"
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

rule SUSP_EXPL_JAR_Indicators_Dec24 {
   meta:
      description = "Detects characteristics of JAR files used during Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
   strings:
      $s1 = "start.java" ascii fullword
      $s2 = "TLS v3 " ascii
      $s3 = "java/util/Base64$Decoder" ascii
   condition:
      uint16(0) == 0xfeca
      and filesize < 20KB
      and all of them
}
