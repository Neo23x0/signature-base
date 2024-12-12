
rule EXPL_Cleo_Exploitation_Log_Indicators_Dec24 : SCRIPT {
   meta:
      description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      id = "385042a9-fc8c-5b50-975f-3436a16e6861"
   strings:
      $x1 = "Note: Processing autorun file 'autorun\\health" ascii wide
      $x2 = "60282967-dc91-40ef-a34c-38e992509c2c.xml" ascii wide
      $x3 = "<Detail level=\"1\">Executing 'cmd.exe /c \"powershell -NonInteractive -EncodedCommand " ascii wide
   condition:
      1 of them
}

rule SUSP_EXPL_Cleo_Exploitation_Log_Indicators_Dec24_1 {
   meta:
      author = "X__Junior"
      description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      hash1 = "786951478a0fc5db24f6e1d8dcc5eaa8880dbd928da97828a61f1f1f0f21e21d"
      date = "2024-12-10"
      score = 75
      id = "81daf184-4c38-5d84-899b-9d0de2f39934"
   strings:
      $sa1 = "<Thread type=\"AutoRun\" action=" ascii
      $sa2 = "<Mark date=" ascii
      $sa3 = "<Event>" ascii
      $sa4 = "<Command text" ascii

      $sb1 = "[System.Net.WebRequest]::create" ascii
      $sb2 = "Invoke-RestMethod" ascii
      $sb3 = "Invoke-WebRequest" ascii
      $sb4 = "iwr " ascii
      $sb5 = "Net.WebClient" ascii
      $sb6 = "Resume-BitsTransfer" ascii
      $sb7 = "Start-BitsTransfer" ascii
      $sb8 = "wget " ascii
      $sb9 = "WinHttp.WinHttpRequest" ascii
      $sb10 = ".DownloadFile(" ascii
      $sb11 = ".DownloadString(" ascii
      $sb12 = "Bypass" nocase ascii
      $sb13 = "-EncodedCommand" ascii
      $sb14 = "-windowstyle hidden" ascii
      $sb15 = " -enc " ascii
   condition:
      filesize < 1MB
      and all of ($sa*)
      and 1 of ($sb*)
}

rule SUSP_EXPL_Cleo_Exploitation_Log_Indicators_Dec24_2 {
   meta:
      author = "X__Junior"
      description = "Detects indicators found in logs during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "d215d4a0-1726-58d4-90df-8ec6102effe1"
   strings:
      $sa1 = "<Thread type=\"AutoRun\" action=" ascii
      $sa2 = "<Mark date=" ascii
      $sa3 = "<Event>" ascii
      $sa4 = "<Command text" ascii

      $sb1 = "wscript" ascii
      $sb2 = "cscript" ascii
      $sb3 = "mshta" ascii
      $sb4 = "certutil" ascii
      $sb5 = "pwsh" ascii
      $sb6 = "curl" ascii
      $sb7 = "msiexec" ascii
      $sb8 = "taskkill" ascii
      $sb9 = "regsvr32" ascii
      $sb10 = "rundll32" ascii
      $sb11 = "bitsadmin" ascii
      $sb12 = "whoami" ascii
      $sb13 = "bcdedit" ascii
      $sb14 = "systeminfo" ascii
      $sb15 = "reg " ascii
      $sb16 = "schtasks" ascii
      // $sb17 = "query" ascii
   condition:
      filesize < 1MB
      and all of ($sa*)
      and 1 of ($sb*)
}

rule EXPL_Cleo_Exploitation_XML_Indicators_Dec24 {
   meta:
      description = "Detects XML used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "622633af-aa7a-5bf9-a59c-6590535d86a4"
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


rule SUSP_EXPL_Cleo_Exploitation_XML_Indicators_Dec24_1 {
   meta:
      author = "X__Junior"
      description = "Detects XML used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      hash1 = "b103f708e85416fc6d7af9605da4b57b3abe42fb9c6c9ec0f539b4c877580bd2"
      date = "2024-12-10"
      score = 70
      id = "b30ca09f-b84c-5de8-9bf7-9f3269f32c1f"
   strings:
      $sa1 = "<Action actiontype=\"Commands\"" ascii
      $sa2 = "<?xml version=" ascii
      $sa3 = "<Runninglocalrequired>" ascii
      $sa4 = "<Autostartup>" ascii

      $sb1 = "[System.Net.WebRequest]::create" ascii
      $sb2 = "Invoke-RestMethod" ascii
      $sb3 = "Invoke-WebRequest" ascii
      $sb4 = "iwr " ascii
      $sb5 = "Net.WebClient" ascii
      $sb6 = "Resume-BitsTransfer" ascii
      $sb7 = "Start-BitsTransfer" ascii
      $sb8 = "wget " ascii
      $sb9 = "WinHttp.WinHttpRequest" ascii
      $sb10 = ".DownloadFile(" ascii
      $sb11 = ".DownloadString(" ascii
      $sb12 = "Bypass" nocase ascii
      $sb13 = "-EncodedCommand" ascii
      $sb14 = "-windowstyle hidden" ascii
      $sb15 = " -enc " ascii
   condition:
      filesize < 10KB
      and all of ($sa*)
      and 1 of ($sb*)
}

rule SUSP_EXPL_Cleo_Exploitation_XML_Indicators_Dec24_2 {
   meta:
      author = "X__Junior"
      description = "Detects XML used during and after Cleo software exploitation (as reported by Huntress in December 2024)"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 70
      id = "a71c71f3-d36f-5c27-b150-e678bccf2dba"
   strings:
      $sa1 = "<Action actiontype=\"Commands\"" ascii
      $sa2 = "<?xml version=" ascii
      $sa3 = "<Runninglocalrequired>" ascii
      $sa4 = "<Autostartup>" ascii

      $sb1 = "wscript" ascii
      $sb2 = "cscript" ascii
      $sb3 = "mshta" ascii
      $sb4 = "certutil" ascii
      $sb5 = "pwsh" ascii
      $sb6 = "curl" ascii
      $sb7 = "msiexec" ascii
      $sb8 = "taskkill" ascii
      $sb9 = "regsvr32" ascii
      $sb10 = "rundll32" ascii
      $sb11 = "bitsadmin" ascii
      $sb12 = "whoami" ascii
      $sb13 = "bcdedit" ascii
      $sb14 = "systeminfo" ascii
      $sb15 = "reg " ascii
      $sb16 = "schtasks" ascii
      // $sb17 = "query" ascii
   condition:
      filesize < 10KB
      and all of ($sa*)
      and 1 of ($sb*)
}

rule EXPL_Cleo_Exploitation_PS1_Indicators_Dec24 : SCRIPT {
   meta:
      description = "Detects encoded and decoded PowerShell loader used during Cleo software exploitation (as reported by Huntress in December 2024)"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      id = "491cda57-0ad0-5ddc-90cb-48411eef2f2e"
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
      id = "4e8f6aa8-9efd-5fcf-b795-5042d4ba1708"
   strings:
      $s1 = "TLS v3 " ascii
      $s2 = "java/util/Base64$Decoder" ascii
      $s3 = "AES/CBC/NoPadding" ascii
      $s4 = "getenv" ascii
      $s5 = "ava/util/zip/ZipInputStream" ascii
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
      id = "2940ddad-3dba-594a-9111-e4741d6ff39b"
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
      id = "bd575454-7fd0-566d-94e5-ec1368675108"
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

rule EXPL_Cleo_Exploitation_JAVA_Payloads_Dec24_3 {
   meta:
      description = "Detects characteristics of JAR files used during Cleo software exploitation"
      author = "X__Junior"
      reference = "https://www.huntress.com/blog/threat-advisory-oh-no-cleo-cleo-software-actively-being-exploited-in-the-wild"
      date = "2024-12-10"
      score = 75
      id = "5c227bb9-0731-5955-a758-6fe86ecc2d86"
   strings:
      $a1 = "java/lang/String" ascii

      $s1 = "#lsz#" ascii
      $s2 = "#dbg#" ascii
      $s3 = "#ll#" ascii
      $s4 = "SvZipDataOverflow=%d OpNotConf=" ascii
   condition:
      uint16(0) == 0xfeca
      and filesize < 20KB
      and 3 of ($s*) and $a1
}