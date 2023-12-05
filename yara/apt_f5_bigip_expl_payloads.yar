
rule MAL_Payload_F5_BIG_IP_Exploitations_Jul20_1 {
   meta:
      description = "Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://research.nccgroup.com/2020/07/05/rift-f5-networks-k52145254-tmui-rce-vulnerability-cve-2020-5902-intelligence/"
      date = "2020-06-07"
      score = 75
      id = "57705ba1-c0ad-5ca6-8539-44d9da6b5942"
   strings:
      $x1 = "rm -f /etc/ld.so.preload" ascii fullword
      $x2 = "echo \"* * * * * $LDR" ascii
      $x3 = ".sh -o /tmp/in.sh" ascii
      $x4 = "chmod a+x /etc/.modules/.tmp" ascii
      $x5 = "chmod +x /var/log/F5-logcheck"

      $s1 = "ulimit -n 65535" ascii fullword
      $s2 = "-s /usr/bin/wget " ascii
      $s3 = ".sh | sh" ascii
   condition:
      filesize < 300KB and
      ( 1 of ($x*) or 3 of them )
}
