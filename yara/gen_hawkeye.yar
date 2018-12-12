
rule HawkEye_Keylogger_Feb18_1 {
   meta:
      description = "Detects HawkEye keylogger variante observed in February 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
      date = "2018-02-12"
      hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
   strings:
      $s1 = "UploadReportLogin.asmx" fullword wide
      $s2 = "tmp.exe" fullword wide
      $s3 = "%appdata%\\" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule MAL_HawkEye_Keylogger_Gen_Dec18 {
   meta:
      description = "Detects HawkEye Keylogger Reborn"
      author = "Florian Roth"
      reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
      date = "2018-12-10"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
   strings:
      $s1 = "HawkEye Keylogger" fullword wide
      $s2 = "_ScreenshotLogger" fullword ascii
      $s3 = "_PasswordStealer" fullword ascii
   condition:
      2 of them
}
