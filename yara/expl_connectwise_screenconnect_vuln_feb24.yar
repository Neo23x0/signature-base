
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

rule SUSP_ScreenConnect_User_Gmail_2024_Feb24 {
   meta:
      description = "Detects suspicious ScreenConnect user with Gmail address created in 2024, which could be a sign of exploitation of the ConnectWise ScreenConnect (versions prior to 23.9.8) vulnerability that allows an Authentication Bypass"
      author = "Florian Roth"
      reference = "https://twitter.com/_johnhammond/status/1760357971127832637"
      date = "2024-02-20"
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
      date = "2024-02-20"
      score = 50
   strings:
      $a1 = "<Users xmlns:xsi="

      $s1 = "<CreationDate>2024-"
   condition:
      filesize < 200KB
      and all of them
      and filepath contains "\\ScreenConnect\\App_Data\\"
}

