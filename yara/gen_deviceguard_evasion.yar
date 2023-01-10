
rule SUSP_DeviceGuard_WDS_Evasion {
   meta:
      author = "Florian Roth"
      description = "Detects WDS file used to circumvent Device Guard"
      score = 70
      date = "2015-01-01"
      modified = "2023-01-06"
      reference = "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html"
   strings:
      $s1 = "r @$ip=@$t0" ascii
      $s2 = ";eb @$t0+" ascii
      $s3 = ".foreach /pS" ascii
   condition:
      filesize < 50KB and all of them
}
