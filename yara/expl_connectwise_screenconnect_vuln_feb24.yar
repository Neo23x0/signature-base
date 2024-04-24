import "pe"

rule ConnectWise_ScreenConnect_Authentication_Bypass_Feb_2024_Exploitation_IIS_Logs {
   meta:
      description = "Detects an http request to '/SetupWizard.aspx/' with anything following it, which when found in IIS logs is a potential indicator of compromise of the 2024 ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Huntress DE&TH Team (modified by Florian Roth)"
      reference = "https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8"
      date = "2024-02-20"
      modified = "2024-02-21"
      id = "2886530b-e164-4c4b-b01e-950e3c40acb4"
   strings:
      $s1 = " GET /SetupWizard.aspx/" ascii
      $s2 = " POST /SetupWizard.aspx/" ascii
      $s3 = " PUT /SetupWizard.aspx/" ascii
      $s4 = " HEAD /SetupWizard.aspx/" ascii
   condition:
      1 of them
}

rule SUSP_ScreenConnect_User_PoC_Com_Unused_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user with poc.com email address, which is a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability with the POC released by WatchTower and the account wasn't actually used yet to login"
      author = "Florian Roth"
      reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
      date = "2024-02-23"
      score = 65
      id = "c57e6c6a-298f-5ff3-b76a-03127ff88699"
   strings:
      $a1 = "<Users xmlns:xsi="
      $a2 = "<CreationDate>"

      $s1 = "@poc.com</Email>"
      $s2 = "<LastLoginDate>0001"
   condition:
      filesize < 200KB
      and all of ($a*)
      and all of ($s*)
}

rule SUSP_ScreenConnect_User_PoC_Com_Used_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user with poc.com email address, which is a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability with the POC released by WatchTower and the account was already used yet to login"
      author = "Florian Roth"
      reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
      date = "2024-02-23"
      score = 75
      id = "91990558-f145-5968-9722-b6815f6ad8d5"
   strings:
      $a1 = "<Users xmlns:xsi="
      $a2 = "<CreationDate>"

      $s1 = "@poc.com</Email>"

      $f1 = "<LastLoginDate>0001"
   condition:
      filesize < 200KB
      and all of ($a*)
      and $s1
      and not 1 of ($f*)
}

rule SUSP_ScreenConnect_Exploitation_Artefacts_Feb24 : SCRIPT {
   meta:
      description = "Detects post exploitation indicators observed by HuntressLabs in relation to the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "079f4153-8bc7-574f-b6fa-af5536b842ab"
   strings:
      $x01 = "-c foreach ($disk in Get-WmiObject Win32_Logicaldisk){Add-MpPreference -ExclusionPath $disk.deviceid}"
      $x02 = ".msi c:\\mpyutd.msi"
      $x03 = "/MyUserName_$env:UserName"
      $x04 = " -OutFile C:\\Windows\\Help\\"
      $x05 = "/Create /TN \\\\Microsoft\\\\Windows\\\\Wininet\\\\UserCache_"
      $x06 = "$e = $r + \"ssh.exe\""
      $x07 = "Start-Process -f $e -a $args -PassThru -WindowStyle Hidden).Id"
      $x08 = "-R 9595:localhost:3389 -p 443 -N -oStrictHostKeyChecking=no "
      $x09 = "chromeremotedesktophost.msi', $env:ProgramData+"
      $x10 = "9595; iwr -UseBasicParsing "
      $x11 = "curl  https://cmctt.]com/pub/media/wysiwyg/"
      $x12 = ":8080/servicetest2.dll"
      $x13 = "/msappdata.msi c:\\mpyutd.msi"
      $x14 = "/svchost.exe -OutFile "
      $x15 = "curl http://minish.wiki.gd"
      $x16 = " -Headers @{'ngrok-skip-browser-warning'='true'} -OutFile "
      $x17 = "rundll32.exe' -Headers @"
      $x18 = "/nssm.exe' -Headers @"
      $x19 = "c:\\programdata\\update.dat UpdateSystem"
      $x20 = "::size -eq 4){\\\"TVqQAA" ascii wide
      $x21 = "::size -eq 4){\"TVqQAA" ascii wide
      $x22 = "-nop -c [System.Reflection.Assembly]::Load(([WmiClass]'root\\cimv2:System_"

      /* Persistence */
      $xp0 = "/add default test@2021! /domain"
      $xp1 = "/add default1 test@2021! /domain"
      $xp2 = "oldadmin Pass8080!!"
      $xp3 = "temp 123123qwE /add "
      $xp4 = "oldadmin \"Pass8080!!\""
      $xp5 = "nssm set xmrig AppDirectory "
   condition:
      1 of ($x*)
}

rule SUSP_Command_Line_Combos_Feb24_2 : SCRIPT {
   meta:
      description = "Detects suspicious command line combinations often found in post exploitation activities"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "d9bc6083-c3ca-5639-a9df-483fea6d0187"
   strings:
      $sa1 = " | iex"
      $sa2 = "iwr -UseBasicParsing "
   condition:
      filesize < 2MB and all of them
}

rule SUSP_PS1_Combo_TransferSH_Feb24 : SCRIPT {
   meta:
      description = "Detects suspicious PowerShell command that downloads content from transfer.sh as often found in loaders"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 70
      id = "fd14cca5-9cf8-540b-9d6e-39ca2c267272"
   strings:
      $x1 = ".DownloadString('https://transfer.sh"
      $x2 = ".DownloadString(\"https://transfer.sh"
      $x3 = "Invoke-WebRequest -Uri 'https://transfer.sh"
      $x4 = "Invoke-WebRequest -Uri \"https://transfer.sh"
   condition:
      1 of them
}

rule MAL_SUSP_RANSOM_LockBit_RansomNote_Feb24 {
   meta:
      description = "Detects the LockBit ransom note file 'LockBit-DECRYPT.txt' which is a sign of a LockBit ransomware infection"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "b2fcb2a7-49e8-520c-944f-6acd5ded579b"
   strings:
      $x1 = ">>>> Your personal DECRYPTION ID:"
   condition:
      1 of them
}

rule MAL_SUSP_RANSOM_Lazy_RansomNote_Feb24 {
   meta:
      description = "Detects the Lazy ransom note file 'HowToRestoreYourFiles.txt' which is a sign of a Lazy ransomware infection"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      id = "287dfd67-8d0d-5906-b593-3af42a5a3aa4"
   strings:
      $x1 = "All Encrypted files can be reversed to original form and become usable"
   condition:
      1 of them
}


rule SUSP_MAL_SigningCert_Feb24_1 {
   meta:
      description = "Detects PE files signed with a certificate used to sign malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "37a39fc1feb4b14354c4d4b279ba77ba51e0d413f88e6ab991aad5dd6a9c231b"
      hash2 = "e8c48250cf7293c95d9af1fb830bb8a5aaf9cfb192d8697d2da729867935c793"
      id = "f25ea77a-1b4e-5c13-9117-eedf0c20335a"
   strings:
      $s1 = "Wisdom Promise Security Technology Co." ascii
      $s2 = "Globalsign TSA for CodeSign1" ascii
      $s3 = { 5D AC 0B 6C 02 5A 4B 21 89 4B A3 C2 }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 70000KB
      and all of them
}

rule MAL_CS_Loader_Feb24_1 {
   meta:
      description = "Detects Cobalt Strike malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "0a492d89ea2c05b1724a58dd05b7c4751e1ffdd2eab3a2f6a7ebe65bf3fdd6fe"
      id = "6c9914a4-b079-5a39-9d3b-7b9a2b54dc2b"
   strings:
      $s1 = "Dll_x86.dll" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 1000KB
      and (
         pe.exports("UpdateSystem") and (
            pe.imphash() == "0dc05c4c21a86d29f1c3bf9cc5b712e0"
            or $s1
         )
      )
}

rule MAL_RANSOM_LockBit_Indicators_Feb24 {
   meta:
      description = "Detects Lockbit ransomware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "a50d9954c0a50e5804065a8165b18571048160200249766bfa2f75d03c8cb6d0"
      id = "108430c8-4fe5-58a1-b709-539b257c120c"
   strings:
      $op1 = { 76 c1 95 8b 18 00 93 56 bf 2b 88 71 4c 34 af b1 a5 e9 77 46 c3 13 }
      $op2 = { e0 02 10 f7 ac 75 0e 18 1b c2 c1 98 ac 46 }
      $op3 = { 8b c6 ab 53 ff 15 e4 57 42 00 ff 45 fc eb 92 ff 75 f8 ff 15 f4 57 42 00 }
   condition:
      uint16(0) == 0x5a4d
      and filesize < 500KB
      and (
         pe.imphash() == "914685b69f2ac2ff61b6b0f1883a054d"
         or 2 of them
      ) or all of them
}

rule MAL_MSI_Mpyutils_Feb24_1 {
   meta:
      description = "Detects malicious MSI package mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709"
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 70
      hash1 = "8e51de4774d27ad31a83d5df060ba008148665ab9caf6bc889a5e3fba4d7e600"
      id = "e7794336-a325-5b92-8c25-81ed9cb28044"
   strings:
      $s1 = "crypt64ult.exe" ascii fullword
      $s2 = "EXPAND.EXE" wide fullword
      $s6 = "ICACLS.EXE" wide fullword
   condition:
      uint16(0) == 0xcfd0
      and filesize < 20000KB
      and all of them
}

rule MAL_Beacon_Unknown_Feb24_1 {
   meta:
      description = "Detects malware samples mentioned in a HuntressLabs report on the exploitation of ScreenConnect vulnerability CVE-2024-1708 and CVE-2024-1709 "
      author = "Florian Roth"
      reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
      date = "2024-02-23"
      score = 75
      hash1 = "6e8f83c88a66116e1a7eb10549542890d1910aee0000e3e70f6307aae21f9090"
      hash2 = "b0adf3d58fa354dbaac6a2047b6e30bc07a5460f71db5f5975ba7b96de986243"
      hash3 = "c0f7970bed203a5f8b2eca8929b4e80ba5c3276206da38c4e0a4445f648f3cec"
      id = "9299fd44-5327-5a73-8299-108b710cb16e"
   strings:
      $s1 = "Driver.dll" wide fullword
      $s2 = "X l.dlT" ascii fullword
      $s3 = "$928c7481-dd27-8e23-f829-4819aefc728c" ascii fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 2000KB
      and 3 of ($s*)
}

/* --------------------------------------------------------------------------------- */
/* only usable with THOR or THOR Lite, e.g. in THOR Cloud */

rule SUSP_ScreenConnect_User_Gmail_2024_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user with Gmail address created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-22"
      score = 65
      id = "3c86f4ee-4e8c-566b-b54e-e94418e4ec7e"
   strings:
      $a1 = "<Users xmlns:xsi="

      $s1 = "@gmail.com</Email>"
      $s2 = "<CreationDate>2024-"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}

rule SUSP_ScreenConnect_New_User_2024_Feb24 {
   meta:
      description = "Detects suspicious new ScreenConnect user created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-22"
      score = 50
      id = "f6675ded-39a4-590a-a201-fcfe3c056e60"
   strings:
      $a1 = "<Users xmlns:xsi="

      $s1 = "<CreationDate>2024-"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}

rule SUSP_ScreenConnect_User_2024_No_Logon_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user created in 2024 but without any login, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://github.com/watchtowrlabs/connectwise-screenconnect_auth-bypass-add-user-poc/blob/45e5b2f699a4d8f2d59ec3fc79a2e3c99db71882/watchtowr-vs-ConnectWise_2024-02-21.py#L53"
      date = "2024-02-23"
      score = 60
      id = "c0861f1c-08e2-565d-a468-2075c51b4004"
   strings:
      $a1 = "<Users xmlns:xsi="
      $a2 = "<CreationDate>"

      $s1 = "<CreationDate>2024-"
      $s2 = "<LastLoginDate>0001-01-01T00:00:00</LastLoginDate>"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}
