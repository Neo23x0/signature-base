
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

rule EXPL_Cleo_Exploitation_JAVA_Payloads_Dec24_1_1 {
   meta:
      description = "Detects characteristics of JAVA files used during Cleo software exploitation (as reported by Huntress in December 2024) - files Cli, ScSlot, Slot, SrvSlot"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      hash1 = "0c57b317b572d071afd8ccdb844dd6f117e20f818c6031d7ba8adcbd32be0617"
   strings:
      $a1 = "java/lang/StringBuffer"

      $x1 = "Start-Sleep 3;del " ascii
      $x2 = "sleep 3;rm -f '" ascii
      $x3 = "powershell -Noninteractive -EncodedCommand " ascii
      $x4 = "runDelFileCmd" ascii fullword
   condition:
      uint16(0) == 0xfeca
      and filesize < 50KB
      and $a1
      and 1 of ($x*)
}

rule EXPL_Cleo_Exploitation_JAVA_Payloads_Dec24_2 {
   meta:
      description = "Detects characteristics of JAVA files used during Cleo software exploitation (as reported by Huntress in December 2024) - file Proc"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      hash1 = "1ba95af21bac45db43ebf02f87ecedde802c7de4d472f33e74ee0a5b5015a726"
   strings:
      $s1 = "Timeout getting pipe-data" ascii fullword
      $s2 = "Ftprootpath" ascii fullword
      $s3 = "Rest cmd=" ascii fullword
      $s4 = "writeToProc" ascii fullword
   condition:
      uint16(0) == 0xfeca
      and filesize < 30KB
      and 3 of them
}
