rule Servantshell {
   meta:
      author = "Arbor Networks ASERT Nov 2015"
      description = "Detects Servantshell malware"
      date = "2017-02-02"
      reference = "https://tinyurl.com/jmp7nrs"
      score = 70
   strings:
      $string1 = "SelfDestruction.cpp"
      $string2 = "SvtShell.cpp"
      $string3 = "InitServant"
      $string4 = "DeinitServant"
      $string5 = "CheckDT"
   condition:
      uint16(0) == 0x5a4d and all of them
}
