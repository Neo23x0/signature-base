rule URL_File_Local_EXE {
   meta:
      description = "Detects an .url file that points to a local executable"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malwareforme/status/915300883012870144"
      date = "2017-10-04"
      score = 60
      id = "8b157e98-7b69-5649-b1d8-40bd6b685bf6"
   strings:
      $s1 = "[InternetShortcut]" ascii wide fullword
      $s2 = /URL=file:\/\/\/C:\\[^\n]{1,50}\.exe/
   condition:
      filesize < 400 and all of them
}
