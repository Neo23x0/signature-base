rule HKTL_PowerSploit {
   meta:
      description = "Detects default strings used by PowerSploit to establish persistence"
      author = "Markus Neis"
      reference = "https://www.hybrid-analysis.com/sample/16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75?environmentId=100" /*MuddyWater*/
      date = "2018-06-23"
      hash1 = "16937e76db6d88ed0420ee87317424af2d4e19117fe12d1364fee35aa2fadb75"
      id = "8cb0753c-c5bb-56fc-b492-4e785f4bdaf4"
   strings:
      $ps = "function" nocase ascii wide
      $s1 = "/Create /RU system /SC ONLOGON" ascii wide
      $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
   condition:
      all of them
}
