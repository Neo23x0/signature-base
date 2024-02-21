
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
   condition:
      1 of them
}
