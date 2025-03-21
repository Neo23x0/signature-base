
rule Ping_Command_in_EXE {
   meta:
      description = "Detects an suspicious ping command execution in an executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2016-11-03"
      score = 60
      id = "937ab622-fbcf-5a31-a3ff-af2584484140"
   strings:
      $x1 = "cmd /c ping 127.0.0.1 -n " ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule GoogleBot_UserAgent {
   meta:
      description = "Detects the GoogleBot UserAgent String in an Executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-01-27"
      score = 65
      id = "621532ac-fc0b-5118-84b0-eac110693320"
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii

      $fp1 = "McAfee, Inc." wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ($fp*) )
}

rule Gen_Net_LocalGroup_Administrators_Add_Command {
   meta:
      description = "Detects an executable that contains a command to add a user account to the local administrators group"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-07-08"
      id = "9f6095fc-6d9f-5814-b407-f320191fd912"
   strings:
      $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule Suspicious_Script_Running_from_HTTP {
   meta:
      description = "Detects a suspicious "
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
      score = 50
      date = "2017-08-20"
      id = "9ba84e9c-a32b-5f66-8d50-75344599cafc"
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition:
      1 of them
}

rule ReconCommands_in_File : FILE {
   meta:
      description = "Detects various recon commands in a single file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/haroonmeer/status/939099379834658817"
      date = "2017-12-11"
      score = 40
      id = "62d59913-5dbd-512c-98ea-044bbb9ac2da"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-01-01"
      score = 80
      id = "60f23d32-0737-501f-bf1c-1ca32af62efc"
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

rule SUSP_PDB_Strings_Keylogger_Backdoor : HIGHVOL {
   meta:
      description = "Detects PDB strings used in backdoors or keyloggers"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-03-23"
      score = 65
      id = "190daadb-0de6-5665-a241-95c374dbda47"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-05-11"
      score = 60
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
      id = "3257aff0-b923-5e56-b67c-fa676341a102"
   strings:
      $s1 = "Microsoft(C) Windows(C) Operating System" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}

rule SUSP_LNK_File_AppData_Roaming {
   meta:
      description = "Detects a suspicious link file that references to AppData Roaming"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 50
      id = "d905e58f-ae2e-5dc2-b206-d0435b023df0"
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2018/05/deep-dive-into-rig-exploit-kit-delivering-grobios-trojan.html"
      date = "2018-05-16"
      score = 40
      id = "f4f6709f-9c4d-5f0c-9826-97444d282adc"
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
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "b30cc10e915a23c7273f0838297e0d2c9f4fc0ac1f56100eef6479c9d036c12b"
      id = "6d3bfdfd-ef8f-5740-ac1f-5835c7ce0f43"
   strings:
      $s1 = "\"c\" & \"r\" & \"i\" & \"p\" & \"t\"" ascii
   condition:
      1 of them
}

rule SUSP_PowerShell_IEX_Download_Combo {
   meta:
      description = "Detects strings found in sample from CN group repo leak in October 2018"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/JaromirHorejsi/status/1047084277920411648"
      date = "2018-10-04"
      hash1 = "13297f64a5f4dd9b08922c18ab100d3a3e6fdeab82f60a4653ab975b8ce393d5"
      id = "1dfedcb0-345c-548c-85ac-3c1e78bfd9e2"
   strings:
      $x1 = "IEX ((new-object net.webclient).download" ascii nocase

      $fp1 = "chocolatey.org"
      $fp2 = "Remote Desktop in the Appveyor"
      $fp3 = "/appveyor/" ascii
   condition:
      $x1 and not 1 of ($fp*)
}

rule SUSP_Win32dll_String {
   meta:
      description = "Detects suspicious string in executables"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@Sebdraven/apt-sidewinder-changes-theirs-ttps-to-install-their-backdoor-f92604a2739"
      date = "2018-10-24"
      hash1 = "7bd7cec82ee98feed5872325c2f8fd9f0ea3a2f6cd0cd32bcbe27dbbfd0d7da1"
      id = "b1c78386-c23d-5138-942a-3da90e5802cc"
   strings:
      $s1 = "win32dll.dll" fullword ascii
   condition:
      filesize < 60KB and all of them
}

rule SUSP_Modified_SystemExeFileName_in_File {
   meta:
      description = "Detecst a variant of a system file name often used by attackers to cloak their activity"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group"
      date = "2018-12-11"
      score = 65
      hash1 = "5723f425e0c55c22c6b8bb74afb6b506943012c33b9ec1c928a71307a8c5889a"
      hash2 = "f1f11830b60e6530b680291509ddd9b5a1e5f425550444ec964a08f5f0c1a44e"
      id = "97d91e1b-49b8-504e-9e9c-6cfb7c2afe41"
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
      modified = "2025-03-20"
      score = 70
      hash1 = "e0112efb63f2b2ac3706109a233963c19750b4df0058cc5b9d3fa1f1280071eb"
      id = "472cbeaf-28e7-51a2-b2e6-96c1d9d05b26"
   strings:
      $a1 = "java/lang/String" ascii

      $s1 = ".vbs" ascii
      $s2 = "createNewFile" fullword ascii
      $s3 = "wscript" fullword ascii nocase

      $fp1 = "com/smm/"
      $fp2 = "install"
   condition:
      ( uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca ) 
      and filesize < 100KB 
      and $a1 
      and all of ($s*)
      and not 1 of ($fp*)
}

rule SUSP_RAR_with_PDF_Script_Obfuscation {
   meta:
      description = "Detects RAR file with suspicious .pdf extension prefix to trick users"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-04-06"
      hash1 = "b629b46b009a1c2306178e289ad0a3d9689d4b45c3d16804599f23c90c6bca5b"
      id = "a3d2f5e9-3052-551b-8b2c-abcdd1ac2e48"
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
      author = "Florian Roth (Nextron Systems)"
      reference = "https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-interface-portproxy"
      date = "2019-04-20"
      score = 65
      hash1 = "9b33a03e336d0d02750a75efa1b9b6b2ab78b00174582a9b2cb09cd828baea09"
      id = "cbbd2042-572c-5283-bd45-e745b36733ad"
   strings:
      $x1 = "netsh interface portproxy add v4tov4 listenport=" ascii
   condition:
      1 of them
}

rule SUSP_DropperBackdoor_Keywords {
   meta:
      description = "Detects suspicious keywords that indicate a backdoor"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      date = "2019-04-24"
      hash1 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
      id = "2942ba6d-a533-5954-bfcf-417262e2fac2"
   strings:
      $x4 = "DropperBackdoor" fullword wide ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule SUSP_SFX_cmd {
   meta:
      description = "Detects suspicious SFX as used by Gamaredon group"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-27"
      hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"
      id = "87e75fe6-c2d7-5cb4-9432-7c37dbfe94b8"
   strings:
      $s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SUSP_XMRIG_Reference {
   meta:
      description = "Detects an executable with a suspicious XMRIG crypto miner reference"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/itaitevet/status/1141677424045953024"
      date = "2019-06-20"
      score = 70
      id = "0a7324ce-90dc-5e6a-b22a-c29eccf324e9"
   strings:
      $x1 = "\\xmrig\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule SUSP_Just_EICAR {
   meta:
      description = "Just an EICAR test file - this is boring but users asked for it"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://2016.eicar.org/85-0-Download.html"
      date = "2019-03-24"
      score = 40
      hash1 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
      id = "e5eedd77-36e2-56a0-be0c-2553043c225a"
   strings:
      $s1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" fullword ascii
   condition:
      uint16(0) == 0x3558 and filesize < 70 and $s1 at 0
}

rule SUSP_PDB_Path_Keywords {
   meta:
      description = "Detects suspicious PDB paths"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1179832666285326337?s=20"
      date = "2019-10-04"
      id = "cbd9b331-58bb-5b29-88a2-5c19f12893a9"
   strings:
      $ = "Debug\\Shellcode" ascii
      $ = "Release\\Shellcode" ascii
      $ = "Debug\\ShellCode" ascii
      $ = "Release\\ShellCode" ascii
      $ = "Debug\\shellcode" ascii
      $ = "Release\\shellcode" ascii
      $ = "shellcode.pdb" nocase ascii
      $ = "\\ShellcodeLauncher" ascii
      $ = "\\ShellCodeLauncher" ascii
      $ = "Fucker.pdb" ascii
      $ = "\\AVFucker\\" ascii
      $ = "ratTest.pdb" ascii
      $ = "Debug\\CVE_" ascii
      $ = "Release\\CVE_" ascii
      $ = "Debug\\cve_" ascii
      $ = "Release\\cve_" ascii
   condition:
      uint16(0) == 0x5a4d and 1 of them
}

rule SUSP_Disable_ETW_Jun20_1 {
   meta:
      description = "Detects method to disable ETW in ENV vars before executing a program"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://gist.github.com/Cyb3rWard0g/a4a115fd3ab518a0e593525a379adee3"
      date = "2020-06-06"
      id = "ea5dee09-959e-5ef2-8f84-5497bdef0a05"
   strings:
      $x1 = "set COMPlus_ETWEnabled=0" ascii wide fullword
      $x2 = "$env:COMPlus_ETWEnabled=0" ascii wide fullword

      $s1 = "Software\\Microsoft.NETFramework" ascii wide
      $sa1 = "/v ETWEnabled" ascii wide fullword 
      $sa2 = " /d 0" ascii wide
      $sb4 = "-Name ETWEnabled"
      $sb5 = " -Value 0 "
   condition:
      1 of ($x*) or 3 of them 
}

rule SUSP_PE_Discord_Attachment_Oct21_1 {
   meta:
      description = "Detects suspicious executable with reference to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-10-12"
      score = 70
      id = "7c217350-4a35-505d-950d-1bc989c14bc2"
   strings:
      $x1 = "https://cdn.discordapp.com/attachments/" ascii wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 5000KB 
      and 1 of them
}

rule SUSP_Encoded_Discord_Attachment_Oct21_1 {
   meta:
      description = "Detects suspicious encoded URL to a Discord attachment (often used for malware hosting on a legitimate FQDN)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2021-10-12"
      score = 70
      id = "06c086f4-8b79-5506-9e3f-b5d099106157"
   strings:
      /* base64 encoded forms */
      $enc_b01 = "Y2RuLmRpc2NvcmRhcHAuY29tL2F0dGFjaG1lbnRz" ascii wide
      $enc_b02 = "Nkbi5kaXNjb3JkYXBwLmNvbS9hdHRhY2htZW50c" ascii wide
      $enc_b03 = "jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudH" ascii wide
      $enc_b04 = "AGMAZABuAC4AZABpAHMAYwBvAHIAZABhAHAAcAAuAGMAbwBtAC8AYQB0AHQAYQBjAGgAbQBlAG4AdABz" ascii wide
      $enc_b05 = "BjAGQAbgAuAGQAaQBzAGMAbwByAGQAYQBwAHAALgBjAG8AbQAvAGEAdAB0AGEAYwBoAG0AZQBuAHQAc" ascii wide
      $enc_b06 = "AYwBkAG4ALgBkAGkAcwBjAG8AcgBkAGEAcABwAC4AYwBvAG0ALwBhAHQAdABhAGMAaABtAGUAbgB0AH" ascii wide

      /* hex encoded forms */
      $enc_h01 = "63646E2E646973636F72646170702E636F6D2F6174746163686D656E7473" ascii wide
      $enc_h02 = "63646e2e646973636f72646170702e636f6d2f6174746163686d656e7473" ascii wide

      /* reversed string */
      $enc_r01 = "stnemhcatta/moc.ppadrocsid.ndc" ascii wide
   condition:
      filesize < 5000KB and 1 of them
}
