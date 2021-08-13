rule DeviceGuard_WDS_Evasion {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
      description = "Detects WDS file used to circumvent Device Guard"
      score = 80
      reference = "http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html"
   strings:
      $s1 = "r @$ip=@$t0" ascii fullword
      $s2 = ";eb @$t0+" ascii
      $s3 = ".foreach /pS" ascii fullword
   condition:
      filesize < 50KB and all of them
}
