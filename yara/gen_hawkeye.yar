
rule HawkEye_Keylogger_Feb18_1 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/ae2521dd-61aa-4bc7-b0d8-8c85ddcbfcc9"
      date = "2018-02-12"
      modified = "2023-01-06"
      score = 90
      hash1 = "bb58922ad8d4a638e9d26076183de27fb39ace68aa7f73adc0da513ab66dc6fa"
      id = "6b4b447f-43d6-5774-a1b9-d53b40364732"
   strings:
      $s1 = "UploadReportLogin.asmx" fullword wide
      $s2 = "tmp.exe" fullword wide
      $s3 = "%appdata%\\" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule MAL_HawkEye_Keylogger_Gen_Dec18 {
   meta:
      description = "Detects HawkEye Keylogger Reborn"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/James_inthe_box/status/1072116224652324870"
      date = "2018-12-10"
      hash1 = "b8693e015660d7bd791356b352789b43bf932793457d54beae351cf7a3de4dad"
      id = "1d06f364-a4e2-5632-ad3a-d53a8cddf072"
   strings:
      $s1 = "HawkEye Keylogger" fullword wide
      $s2 = "_ScreenshotLogger" ascii
      $s3 = "_PasswordStealer" ascii
   condition:
      2 of them
}
