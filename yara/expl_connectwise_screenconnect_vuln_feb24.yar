
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

/* only usable with THOR or THOR Lite, e.g. in THOR Cloud */

rule SUSP_ScreenConnect_User_Gmail_2024_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user with Gmail address created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-22"
      score = 65
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
