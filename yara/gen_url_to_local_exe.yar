rule URL_File_Local_EXE {
   meta:
      description = "Detects an .url file that points to a local executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      reference = "https://twitter.com/malwareforme/status/915300883012870144"
      date = "2017-10-04"
      score = 60
   strings:
      $s1 = "[InternetShortcut]" ascii wide fullword
      $s2 = /URL=file:\/\/\/C:\\[^\n]{1,50}\.exe/
   condition:
      filesize < 400 and all of them
}
