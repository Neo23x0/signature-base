
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

rule Gen_Net_LocalGroup_Administrators_Add_Command {
   meta:
      description = "Detects an executable that contains a command to add a user account to the local administrators group"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-08"
   strings:
      $x1 = /net localgroup administrators [a-zA-Z0-9]{1,16} \/add/ nocase ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them )
}

rule Suspicious_Script_Running_from_HTTP {
   meta:
      description = "Detects a suspicious "
      author = "Florian Roth"
      reference = "https://www.hybrid-analysis.com/sample/a112274e109c5819d54aa8de89b0e707b243f4929a83e77439e3ff01ed218a35?environmentId=100"
      score = 50
      date = "2017-08-20"
   strings:
      $s1 = "cmd /C script:http://" ascii nocase
      $s2 = "cmd /C script:https://" ascii nocase
      $s3 = "cmd.exe /C script:http://" ascii nocase
      $s4 = "cmd.exe /C script:https://" ascii nocase
   condition:
      1 of them
}
