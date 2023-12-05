
rule Scarcruft_malware_Feb18_1 {
   meta:
      description = "Detects Scarcruft malware - February 2018"
      author = "Florian rootpath"
      reference = "https://twitter.com/craiu/status/959477129795731458"
      date = "2018-02-03"
      score = 90
      id = "43a87f2a-cf60-5035-8d40-c360a789a1ac"
   strings:
      $x1 = "d:\\HighSchool\\version 13\\2ndBD\\T+M\\" ascii
      $x2 = "cmd.exe /C ping 0.1.1.2" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}
