/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-03
   Identifier: Operation Cloud Hopper
*/

/* Rule Set ----------------------------------------------------------------- */

rule OpCloudHopper_Malware_1 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "27876dc5e6f746ff6003450eeea5e98de5d96cbcba9e4694dad94ca3e9fb1ddc"
   strings:
      $s1 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s2 = "z{[ZZYUKKKIIGGGGGGGGGGGGG" fullword ascii
      $s3 = "EEECEEC" fullword ascii
      $s4 = "IIEFEE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule OpCloudHopper_Malware_2 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "c1dbf481b2c3ba596b3542c7dc4e368f322d5c9950a78197a4ddbbaacbd07064"
   strings:
      $x1 = "sERvEr.Dll" fullword ascii
      $x2 = "ToolbarF.dll" fullword wide
      $x3 = ".?AVCKeyLoggerManager@@" fullword ascii
      $x4 = "GH0STCZH" ascii

      $s1 = "%%SystemRoot%%\\System32\\svchost.exe -k \"%s\"" fullword wide
      $s2 = "rundll32.exe \"%s\", UnInstall /update %s" fullword wide
      $s3 = "\\Release\\Loader.pdb" fullword ascii
      $s4 = "%s\\%x.dll" fullword wide
      $s5 = "Mozilla/4.0 (compatible)" fullword wide
      $s6 = "\\syslog.dat" fullword wide
      $s7 = "NSOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide

      $op1 = { 8d 34 17 8d 49 00 8a 14 0e 3a 14 29 75 05 41 3b }
      $op2 = { 83 e8 14 78 cf c1 e0 06 8b f8 8b c3 8a 08 84 c9 }
      $op3 = { 3b fb 7d 3f 8a 4d 14 8d 45 14 84 c9 74 1b 8a 14 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) or 3 of ($s*) ) or all of ($op*) ) or ( 6 of them )
}

rule OpCloudHopper_Malware_3 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "c21eaadf9ffc62ca4673e27e06c16447f103c0cf7acd8db6ac5c8bd17805e39d"
   strings:
      $s6 = "operator \"\" " fullword ascii
      $s7 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s11 = "InvokeMainViaCRT" fullword ascii
      $s12 = ".?AVAES@@" fullword ascii

      $op1 = { b6 4c 06 f5 32 cf 88 4c 06 05 0f b6 4c 06 f9 32 }
      $op2 = { 06 fc eb 03 8a 5e f0 85 c0 74 05 8a 0c 06 eb 03 }
      $op3 = { 7e f8 85 c0 74 06 8a 74 06 08 eb 03 8a 76 fc 85 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( all of ($s*) and 1 of ($op*) ) or all of ($op*) ) or ( 5 of them )
}

rule OpCloudHopper_Dropper_1 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "411571368804578826b8f24f323617f51b068809b1c769291b21125860dc3f4e"
   strings:
      $s1 = "{\\version2}{\\edmins0}{\\nofpages1}{\\nofwords11}{\\nofchars69}{\\*\\company google}{\\nofcharsws79}{\\vern24611}{\\*\\password" ascii
   condition:
      ( uint16(0) == 0x5c7b and filesize < 700KB and all of them )
}

rule OpCloudHopper_Malware_4 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "ae6b45a92384f6e43672e617c53a44225e2944d66c1ffb074694526386074145"
   strings:
      $s6 = "operator \"\" " fullword ascii
      $s9 = "InvokeMainViaCRT" fullword ascii
      $s10 = ".?AVAES@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and all of them )
}

rule OpCloudHopper_Malware_5 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "beb1bc03bb0fba7b0624f8b2330226f8a7da6344afd68c5bc526f9d43838ef01"
   strings:
      $x1 = "CWINDOWSSYSTEMROOT" fullword ascii
      $x2 = "YJ_D_KROPOX_M_NUJI_OLY_S_JU_MOOK" fullword ascii
      $x3 = "NJK_JK_SED_PNJHGFUUGIOO_PIY" fullword ascii
      $x4 = "c_VDGQBUl}YSB_C_VDlqSDYFU" fullword ascii

      $s7 = "FALLINLOVE" fullword ascii

      $op1 = { 83 ec 60 8d 4c 24 00 e8 6f ff ff ff 8d 4c 24 00 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 2 of them ) ) or ( 4 of them )
}

rule OpCloudHopper_Malware_6 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "aabebea87f211d47f72d662e2449009f83eac666d81b8629cf57219d0ce31af6"
   strings:
      $s1 = "YDNCCOVZKXGRVQPOBRNXXQVNQYXBBCONCOQEGYELIRBEYOVODGXCOXTHXPCXNGUCHRVWKKZSYQMAOWWGHRSPRGSEUWYMEFZHRTHO" fullword ascii
      $s2 = "psychiatry.dat" fullword ascii
      $s3 = "meekness.lnk" fullword ascii
      $s4 = "SOFTWARE\\EGGORG" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule OpCloudHopper_Malware_7 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "44a7bea8a08f4c2feb74c6a00ff1114ba251f3dc6922ea5ffab9e749c98cbdce"
   strings:
      $x1 = "jepsjepsjepsjepsjepsjepsjepsjepsjepsjeps" fullword ascii
      $x2 = "extOextOextOextO" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule OpCloudHopper_Malware_8 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "19aa5019f3c00211182b2a80dd9675721dac7cfb31d174436d3b8ec9f97d898b"
      hash2 = "5cebc133ae3b6afee27beb7d3cdb5f3d675c3f12b7204531f453e99acdaa87b1"
   strings:
      $s1 = "WSHELL32.dll" fullword wide
      $s2 = "operator \"\" " fullword ascii
      $s3 = "\" /t REG_SZ /d \"" fullword wide
      $s4 = " /f /v \"" fullword wide
      $s5 = "zok]\\\\\\ZZYYY666564444" fullword ascii
      $s6 = "AFX_DIALOG_LAYOUT" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and 4 of them )
}

rule OpCloudHopper_Malware_9 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "f0002b912135bcee83f901715002514fdc89b5b8ed7585e07e482331e4a56c06"
   strings:
      $s1 = "MsMpEng.exe" fullword ascii
      $op0 = { 2b c7 50 e8 22 83 ff ff ff b6 c0 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule OpCloudHopper_Malware_10 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "5b4028728d8011a2003b7ce6b9ec663dd6a60b7adcc20e2125da318e2d9e13f4"
   strings:
      $x1 = "bakshell.EXE" fullword wide
      $s19 = "bakshell Applicazione MFC" fullword wide
      $op0 = { 83 c4 34 c3 57 8b ce e8 92 18 00 00 68 20 70 40 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule OpCloudHopper_Malware_11 {
   meta:
      description = "Detects malware from Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/issues/cyber-security-data-privacy/insights/operation-cloud-hopper.html"
      date = "2017-04-03"
      hash1 = "a80f6c57f772f20d63021c8971a280c19e8eafe7cc7088344c598d84026dda15"
   strings:
      $x1 = "IOGVWDWCXZVRHTE" fullword ascii

      $op1 = { c9 c3 56 6a 00 8b f1 6a 64 e8 dd 34 00 00 c7 06 } /* Opcode */
      $op2 = { 68 38 00 41 00 68 34 00 41 00 e8 d3 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-07
   Identifier: Operation Cloud Hopper - Related
*/

/* Rule Set ----------------------------------------------------------------- */

rule OpCloudHopper_lockdown {
   meta:
      description = "Tools related to Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "8ca61cef74573d9c1d19b8191c23cbd2b7a1195a74eaba037377e5ee232b1dc5"
   strings:
      $s1 = "lockdown.dll" fullword ascii
      $s3 = "mfeann.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule OpCloudHopper_WindowXarBot {
   meta:
      description = "Malware related to Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
   strings:
      $s1 = "\\Release\\WindowXarbot.pdb" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}

rule OpCloudHopper_WmiDLL_inMemory {
   meta:
      description = "Malware related to Operation Cloud Hopper - Page 25"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
   strings:
      $s1 = "wmi.dll 2>&1" ascii
   condition:
      all of them
}

rule OpCloudHopper_Cloaked_PSCP {
   meta:
      description = "Tool used in Operation Cloud Hopper - pscp.exe cloaked as rundll32.exe"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      score = 90
   strings:
      $s1 = "AES-256 SDCTR" ascii
      $s2 = "direct-tcpip" ascii
   condition:
      all of them and filename == "rundll32.exe"
}

rule VBS_WMIExec_Tool_Apr17_1 {
   meta:
      description = "Tools related to Operation Cloud Hopper"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "21bc328ed8ae81151e7537c27c0d6df6d47ba8909aebd61333e32155d01f3b11"
   strings:
      $x1 = "strNetUse = \"cmd.exe /c net use \\\\\" & host" fullword ascii
      $x2 = "localcmd = \"cmd.exe /c \" & command " ascii
      $x3 = "& \" > \" & TempFile & \" 2>&1\"  '2>&1 err" fullword ascii
      $x4 = "strExec = \"cmd.exe /c \" & cmd & \" >> \" & resultfile & \" 2>&1\"  '2>&1 err" fullword ascii
      $x5 = "TempFile = objShell.ExpandEnvironmentStrings(\"%TEMP%\") & \"\\wmi.dll\"" fullword ascii

      $a1 = "WMIEXEC ERROR: Command -> " ascii
      $a2 = "WMIEXEC : Command result will output to" fullword ascii
      $a3 = "WMIEXEC : Target ->" fullword ascii
      $a4 = "WMIEXEC : Login -> OK" fullword ascii
      $a5 = "WMIEXEC : Process created. PID:" fullword ascii
   condition:
      ( filesize < 40KB and 1 of them ) or 3 of them
}
