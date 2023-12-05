
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-05-18
   Identifier: EternalRocks
   Reference: https://twitter.com/stamparm/status/864865144748298242
*/

/* Rule Set ----------------------------------------------------------------- */

rule EternalRocks_taskhost {
   meta:
      description = "Detects EternalRocks Malware - file taskhost.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stamparm/status/864865144748298242"
      date = "2017-05-18"
      hash1 = "cf8533849ee5e82023ad7adbdbd6543cb6db596c53048b1a0c00b3643a72db30"
      id = "8926cdf8-6a3c-5237-80f5-bda9efb39a32"
   strings:
      $x1 = "EternalRocks.exe" fullword wide

      $s1 = "sTargetIP" fullword ascii
      $s2 = "SERVER_2008R2_SP0" fullword ascii
      $s3 = "20D5CCEE9C91A1E61F72F46FA117B93FB006DB51" fullword ascii
      $s4 = "9EBF75119B8FC7733F77B06378F9E735D34664F6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and 1 of ($x*) or 3 of them )
}

rule EternalRocks_svchost {
   meta:
      description = "Detects EternalRocks Malware - file taskhost.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stamparm/status/864865144748298242"
      date = "2017-05-18"
      hash1 = "589af04a85dc66ec6b94123142a17cf194decd61f5d79e76183db026010e0d31"
      id = "c38d3faa-06a2-5f57-a917-91974941352f"
   strings:
      $s1 = "WczTkaJphruMyBOQmGuNRtSNTLEs" fullword ascii
      $s2 = "svchost.taskhost.exe" fullword ascii
      $s3 = "ConfuserEx v" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 2 of them )
}
