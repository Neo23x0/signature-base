rule PLEAD_Downloader_Jun18_1 {
   meta:
      description = "Detects PLEAD Downloader"
      author = "Florian Roth"
      reference = "https://blog.jpcert.or.jp/2018/06/plead-downloader-used-by-blacktech.html"
      date = "2018-06-16"
      hash1 = "a26df4f62ada084a596bf0f603691bc9c02024be98abec4a9872f0ff0085f940"
   strings:
      $s1 = "%02d:%02d:%02d" ascii fullword
      $s2 = "%02d-%02d-%02d" ascii fullword
      $s3 = "1111%02d%02d%02d_%02d%02d2222" ascii fullword
      $a1 = "Scanning..." wide fullword
      $a2 = "Checking..." wide fullword
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
            all of ($s*) or
            ( 2 of ($s*) and 1 of ($a*) )
      )
}
