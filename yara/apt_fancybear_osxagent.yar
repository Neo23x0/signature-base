rule MAL_OSX_FancyBear_Agent_Jul18_1 {
   meta:
      description = "Detects FancyBear Agent for OSX"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/DrunkBinary/status/1018448895054098432"
      date = "2018-07-15"
      hash1 = "d3be93f6ce59b522ff951cef9d59ef347081ffe33d4203cd5b5df0aaa9721aa2"
      id = "ae717f70-7196-561a-916f-1598ab38c77a"
   strings:
      $x1 = "/Users/kazak/Desktop/" ascii

      $s1 = "launchctl load -w ~/Library/LaunchAgents/com.apple.updates.plist" fullword ascii
      $s2 = "mkdir -p /Users/Shared/.local/ &> /dev/null" fullword ascii
      $s3 = "chmod 755 /Users/Shared/start.sh" fullword ascii
      $s4 = "chmod 755 %s/%s &> /dev/null" fullword ascii
      $s6 = "chmod 755 /Users/Shared/.local/kextd" fullword ascii
   condition:
      uint16(0) == 0xfacf and filesize < 3000KB and ( 1 of ($x*) and 4 of them )
}
