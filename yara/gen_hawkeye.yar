
rule HawkEye_Keylogger_Feb18_1 {
   meta:
      description = "Detects HawkEye keylogger variante observed in February 2018"
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
