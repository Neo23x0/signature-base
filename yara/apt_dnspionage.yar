
rule MAL_DNSPIONAGE_Malware_Nov18 {
   meta:
      description = "Detects DNSpionage Malware"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/2018/11/dnspionage-campaign-targets-middle-east.html"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      date = "2018-11-30"
      hash1 = "2010f38ef300be4349e7bc287e720b1ecec678cacbf0ea0556bcf765f6e073ec"
      hash2 = "45a9edb24d4174592c69d9d37a534a518fbe2a88d3817fc0cc739e455883b8ff"
   strings:
      $x1 = ".0ffice36o.com" fullword ascii

      $s1 = "/Client/Login?id=" fullword ascii
      $s2 = ".\\Configure.txt" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko" fullword ascii
      $s6 = "Content-Disposition: form-data; name=\"txts\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and ( 1 of ($x*) or 2 of them )
}

rule APT_DNSpionage_Karkoff_Malware_Apr19_1 {
   meta:
      description = "Detects DNSpionage Karkoff malware"
      author = "Florian Roth"
      reference = "https://blog.talosintelligence.com/2019/04/dnspionage-brings-out-karkoff.html"
      date = "2019-04-24"
      hash1 = "6a251ed6a2c6a0a2be11f2a945ec68c814d27e2b6ef445f4b2c7a779620baa11"
      hash2 = "b017b9fc2484ce0a5629ff1fed15bca9f62f942eafbb74da6a40f40337187b04"
      hash3 = "5b102bf4d997688268bab45336cead7cdf188eb0d6355764e53b4f62e1cdf30c"
      hash4 = "cd4b9d0f2d1c0468750855f0ed352c1ed6d4f512d66e0e44ce308688235295b5"
   strings:
      $x1 = "Karkoff.exe" fullword wide
      $x2 = "kuternull.com" fullword wide
      $x3 = "rimrun.com" fullword wide

      $s1 = "C:\\Windows\\Temp\\" wide
      $s2 = "CMD.exe" fullword wide
      $s3 = "get_ProcessExtensionDataNames" fullword ascii
      $s4 = "get_ProcessDictionaryKeys" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         1 of ($x*) or
         all of ($s*)
      )
}
