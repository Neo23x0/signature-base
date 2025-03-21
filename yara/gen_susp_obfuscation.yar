
rule SUSP_Base64_Encoded_Hex_Encoded_Code {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Detects hex encoded code that has been base64 encoded"
      date = "2019-04-29"
      score = 65
      reference = "https://www.nextron-systems.com/2019/04/29/spotlight-threat-hunting-yara-rule-example/"
      id = "2cfd278f-ff45-5e23-b552-dad688ab303b"
   strings:
      $x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
      $x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }

      $fp1 = "Microsoft Azure Code Signp$"
   condition:
      1 of ($x*) and not 1 of ($fp*)
}

rule SUSP_Double_Base64_Encoded_Executable {
   meta:
      description = "Detects an executable that has been encoded with base64 twice"
      author = "Florian Roth"
      reference = "https://twitter.com/TweeterCyber/status/1189073238803877889"
      score = 70
      date = "2019-10-29"
      modified = "2025-03-21"
      hash = "ef2fc4e10cadb9a1e890208e8ec634d09bb505cce87a3c91a80e5c796bfafb43"
      hash = "f40c6116c05fbd0433fe4031a896e882c5d31059b93b5015a019c04e2a1add32"
      hash = "e396d1e1957e12595250ff85a7613873a065177c6e5b665e0f2b9f14224e33a3"
      hash = "ea96c8696d48884f337e19dfa4220c13200a28192220ebb1a856a7fd850dff99"
   strings:
   /* Double encoded MSDOS stubs
   This program cannot be run in DOS mode
   This program must be run under Win32
   https://ygdrasil.nextron:8000/#recipe=Fork('%5C%5Cn','%5C%5Cn',false)Show_Base64_offsets('A-Za-z0-9%2B/%3D',false,'Raw')Fork('%5C%5Cn','%5C%5Cn',false)Show_Base64_offsets('A-Za-z0-9%2B/%3D',false,'Raw')&input=VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUKVGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVyIFdpbjMy
   */
      $ = "VkdocGN5QndjbTluY21GdElHTmhibTV2ZENCaVpTQnlkVzRnYVc0Z1JFOVRJRzF2Wk" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJR05oYm01dmRDQmlaU0J5ZFc0Z2FXNGdSRTlUSUcxdlpH" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUdOaGJtNXZkQ0JpWlNCeWRXNGdhVzRnUkU5VElHMXZaR" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0JqWVc1dWIzUWdZbVVnY25WdUlHbHVJRVJQVXlCdGIyUm" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCallXNXViM1FnWW1VZ2NuVnVJR2x1SUVSUFV5QnRiMlJs" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQmpZVzV1YjNRZ1ltVWdjblZ1SUdsdUlFUlBVeUJ0YjJSb" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdZMkZ1Ym05MElHSmxJSEoxYmlCcGJpQkVUMU1nYlc5a1" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnWTJGdWJtOTBJR0psSUhKMWJpQnBiaUJFVDFNZ2JXOWta" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ1kyRnVibTkwSUdKbElISjFiaUJwYmlCRVQxTWdiVzlrW" ascii wide
      $ = "VkdocGN5QndjbTluY21GdElHMTFjM1FnWW1VZ2NuVnVJSFZ1WkdWeUlGZHBiak15" ascii wide
      $ = "ZHaHBjeUJ3Y205bmNtRnRJRzExYzNRZ1ltVWdjblZ1SUhWdVpHVnlJRmRwYmpNe" ascii wide
      $ = "WR2hwY3lCd2NtOW5jbUZ0SUcxMWMzUWdZbVVnY25WdUlIVnVaR1Z5SUZkcGJqTX" ascii wide
      $ = "Um9hWE1nY0hKdlozSmhiU0J0ZFhOMElHSmxJSEoxYmlCMWJtUmxjaUJYYVc0ek" ascii wide
      $ = "JvYVhNZ2NISnZaM0poYlNCdGRYTjBJR0psSUhKMWJpQjFibVJsY2lCWGFXNHpN" ascii wide
      $ = "Sb2FYTWdjSEp2WjNKaGJTQnRkWE4wSUdKbElISjFiaUIxYm1SbGNpQlhhVzR6T" ascii wide
      $ = "VWFHbHpJSEJ5YjJkeVlXMGdiWFZ6ZENCaVpTQnlkVzRnZFc1a1pYSWdWMmx1TX" ascii wide
      $ = "VhR2x6SUhCeWIyZHlZVzBnYlhWemRDQmlaU0J5ZFc0Z2RXNWtaWElnVjJsdU16" ascii wide
      $ = "VYUdseklIQnliMmR5WVcwZ2JYVnpkQ0JpWlNCeWRXNGdkVzVrWlhJZ1YybHVNe" ascii wide
   condition:
      1 of them
      and not filepath contains "\\User Data\\Default\\Cache\\" // chrome cache
      and not filepath contains "\\cache2\\entries\\" // FF cache
      and not filepath contains "\\Microsoft\\Windows\\INetCache\\IE\\" // old IE
}

rule SUSP_Reversed_Base64_Encoded_EXE : FILE {
   meta:
      description = "Detects an base64 encoded executable with reversed characters"
      author = "Florian Roth (Nextron Systems)"
      date = "2020-04-06"
      reference = "Internal Research"
      score = 80
      hash1 = "7e6d9a5d3b26fd1af7d58be68f524c4c55285b78304a65ec43073b139c9407a8"
      id = "3b52e59e-7c0a-560f-8123-1099c52e7e3d"
   strings:
      $s1 = "AEAAAAEQATpVT"
      $s2 = "AAAAAAAAAAoVT"
      $s3 = "AEAAAAEAAAqVT"
      $s4 = "AEAAAAIAAQpVT"
      $s5 = "AEAAAAMAAQqVT"

      $sh1 = "SZk9WbgM1TEBibpBib1JHIlJGI09mbuF2Yg0WYyd2byBHIzlGaU" ascii
      $sh2 = "LlR2btByUPREIulGIuVncgUmYgQ3bu5WYjBSbhJ3ZvJHcgMXaoR" ascii
      $sh3 = "uUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGV" ascii
   condition:
      filesize < 10000KB and 1 of them
}

rule SUSP_Script_Base64_Blocks_Jun20_1 {
   meta:
      description = "Detects suspicious file with base64 encoded payload in blocks"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://posts.specterops.io/covenant-v0-5-eee0507b85ba"
      date = "2020-06-05"
      score = 70
      id = "cef759a5-b02a-53e7-bf27-184eee6bc3fa"
   strings:
      $sa1 = "<script language=" ascii
      $sb2 = { 41 41 41 22 2B 0D 0A 22 41 41 41 }
   condition:
      all of them
}

rule SUSP_Reversed_Hacktool_Author : FILE {
   meta:
      description = "Detects a suspicious path traversal into a Windows folder"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/"
      date = "2020-06-10"
      score = 65
      id = "33e20d75-af07-5df2-82c3-c48aec37a947"
   strings:
      $x1 = "iwiklitneg" fullword ascii wide
      $x2 = " eetbus@ " ascii wide
   condition:
      filesize < 4000KB and
      1 of them
}

rule SUSP_Base64_Encoded_Hacktool_Dev {
   meta:
      description = "Detects a suspicious base64 encoded keyword"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/cyb3rops/status/1270626274826911744"
      date = "2020-06-10"
      score = 65
      id = "6dc7db4b-a614-51e4-a9a5-f869154dbbb1"
   strings:
      $ = "QGdlbnRpbGtpd2" ascii wide 
      $ = "BnZW50aWxraXdp" ascii wide 
      $ = "AZ2VudGlsa2l3a" ascii wide
      $ = "QGhhcm1qMH" ascii wide
      $ = "BoYXJtajB5" ascii wide
      $ = "AaGFybWowe" ascii wide
      $ = "IEBzdWJ0ZW" ascii wide
      $ = "BAc3VidGVl" ascii wide
      $ = "gQHN1YnRlZ" ascii wide
   condition:
      filesize < 6000KB and 1 of them
}
