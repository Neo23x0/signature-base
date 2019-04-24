
rule Ping_Command_in_EXE {
   meta:
      description = "Detects an suspicious ping command execution in an executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-11-03"
      score = 60
   strings:
      $x1 = "cmd /c ping 127.0.0.1 -n " ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule GoogleBot_UserAgent {
   meta:
      description = "Detects the GoogleBot UserAgent String in an Executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-27"
      score = 65
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii

      $fp1 = "McAfee, Inc." wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ($fp*) )
}

rule Gen_Net_LocalGroup_Administrators_Add_Command {
   meta:
      description = "Detects an executable that contains a command to add a user account to the local administrators group"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-08"
   strings:
      $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule Suspicious_Script_Running_from_HTTP {
   meta:
      description = "Detects a suspicious "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
      score = 50
      date = "2017-08-20"
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition:
      1 of them
}

rule ReconCommands_in_File {
   meta:
      description = "Detects various recon commands in a single file"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/haroonmeer/status/939099379834658817"
      date = "2017-12-11"
      score = 40
   strings:
      $ = "tasklist"
      $ = "net time"
      $ = "systeminfo"
      $ = "whoami"
      $ = "nbtstat"
      $ = "net start"
      $ = "qprocess"
      $ = "nslookup"
   condition:
      filesize < 5KB and 4 of them
}

rule VBS_dropper_script_Dec17_1 {
   meta:
      description = "Detects a supicious VBS script that drops an executable"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-01-01"
      score = 80
   strings:
      $s1 = "TVpTAQEAAAAEAA" // 14 samples in goodware archive
      $s2 = "TVoAAAAAAAAAAA" // 26 samples in goodware archive
      $s3 = "TVqAAAEAAAAEAB" // 75 samples in goodware archive
      $s4 = "TVpQAAIAAAAEAA" // 168 samples in goodware archive
      $s5 = "TVqQAAMAAAAEAA" // 28,529 samples in goodware archive

      $a1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition:
      filesize < 600KB and $a1 and 1 of ($s*)
}

rule SUSP_PDB_Strings_Keylogger_Backdoor {
   meta:
      description = "Detects PDB strings used in backdoors or keyloggers"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-03-23"
      score = 65
   strings:
      $ = "\\Release\\PrivilegeEscalation"
      $ = "\\Release\\KeyLogger"
      $ = "\\Debug\\PrivilegeEscalation"
      $ = "\\Debug\\KeyLogger"
      $ = "Backdoor\\KeyLogger_"
      $ = "\\ShellCode\\Debug\\"
      $ = "\\ShellCode\\Release\\"
      $ = "\\New Backdoor"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB
      and 1 of them
}

rule SUSP_Microsoft_Copyright_String_Anomaly_2 {
   meta:
      description = "Detects Floxif Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11"
      score = 60
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
   strings:
      $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_LNK_File_AppData_Roaming {
   meta:
      description = "Detects a suspicious link file that references to AppData Roaming"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 50
   strings:
      $s2 = "AppData" fullword wide
      $s3 = "Roaming" fullword wide
      /* .exe\x00C:\Users\ */
      $s4 = { 00 2E 00 65 00 78 00 65 00 2E 00 43 00 3A 00 5C
              00 55 00 73 00 65 00 72 00 73 00 5C }
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         filesize < 1KB and
         all of them
      )
}

rule SUSP_LNK_File_PathTraversal {
   meta:
      description = "Detects a suspicious link file that references a file multiple folders lower than the link itself"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 40
   strings:
      $s1 = "..\\..\\..\\..\\..\\"
   condition:
      uint16(0) == 0x004c and uint32(4) == 0x00021401 and (
         filesize < 1KB and
         all of them
      )
}

rule SUSP_Script_Obfuscation_Char_Concat {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
   strings:
      $s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii
   condition:
      1 of them
}

rule SUSP_PowerShell_IEX_Download_Combo {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "13297f64a5f4dd9b08922c18ab100d3a3e6fdeab82f60a4653ab975b8ce393d5"
   strings:
      $x1 = "IEX ((new-object net.webclient).download" ascii nocase
   condition:
      1 of them
}

rule SUSP_Win32dll_String {
   meta:
      description = "Detects suspicious string in executables"
      author = "Florian Roth"
      reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
      date = "2018-10-24"
      hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
   strings:
      $s1 = "win32dll.dll" fullword ascii
   condition:
      filesize < 60KB and all of them
}

rule SUSP_Modified_SystemExeFileName_in_File {
   meta:
      description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
      author = "Florian Roth"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11"
      score = 65
      hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
      hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
   strings:
      $s1 = "svchosts.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_JAVA_Class_with_VBS_Content {
   meta:
      description = "Detects a JAVA class file with strings known from VBS files"
      author = "Florian Roth"
      reference = "https://www.menlosecurity.com/blog/a-jar-full-of-problems-for-financial-services-companies"
      date = "2019-01-03"
      score = 60
      hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
   strings:
      $a1 = "java/lang/String" ascii

      $s1 = ".vbs" ascii
      $s2 = "createNewFile" fullword ascii
      $s3 = "wscript" fullword ascii nocase
   condition:
      uint16(0) == 0xfeca and filesize < 100KB and $a1 and 3 of ($s*)
}

rule SUSP_RAR_with_PDF_Script_Obfuscation {
   meta:
      description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2019-04-06"
      hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
   strings:
      $s1 = ".pdf.vbe" ascii
      $s2 = ".pdf.vbs" ascii
      $s3 = ".pdf.ps1" ascii
      $s4 = ".pdf.bat" ascii
      $s5 = ".pdf.exe" ascii
   condition:
      uint32(0) == 0x21726152 and 1 of them
}

rule SUSP_Netsh_PortProxy_Command {
   meta:
      description = "Detects a suspicious command line with netsh and the portproxy command"
      author = "Florian Roth"
      reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
      date = "2019-04-20"
      score = 65
      hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
   strings:
      $x1 = "netsh interface portproxy add v4tov4 listenport=" ascii
   condition:
      1 of them
}

rule SUSP_DropperBackdoor_Keywords {
   meta:
      description = "Detects suspicious keywords that indicate a backdoor"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      date = "2019-04-24"
      hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
   strings:
      $x4 = "DropperBackdoor" fullword wide ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule SUSP_SFX_cmd {
   meta:
      description = "Detects suspicious SFX as used by Gamaredon group"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-09-27"
      hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"
   strings:
      $s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}
