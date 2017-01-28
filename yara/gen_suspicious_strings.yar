
rule Ping_Command_in_EXE {
   meta:
      description = "Detects an suspicious ping command execution in an executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-11-03"
      score = 60
   strings:
      $x1 = "cmd /c ping 127.0.0.1 -n " ascii
   condition:
      uint16(0) == 0x5a4d and all of them
}

rule GoogleBot_UserAgent {
   meta:
      description = "Detects the GoogleBot UserAgent String in an Executable"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-27"
      score = 65
   strings:
      $x1 = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" fullword ascii

      $fp1 = "McAfee, Inc." wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and $x1 and not 1 of ($fp*) )
}
