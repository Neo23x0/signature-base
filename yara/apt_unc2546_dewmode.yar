
rule WEBSHELL_APT_PHP_DEWMODE_UNC2546_Feb21_1 {
   meta:
      description = "Detects DEWMODE webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.fireeye.com/blog/threat-research/2021/02/accellion-fta-exploited-for-data-theft-and-extortion.html"
      date = "2021-02-22"
      hash1 = "2e0df09fa37eabcae645302d9865913b818ee0993199a6d904728f3093ff48c7"
      hash2 = "5fa2b9546770241da7305356d6427847598288290866837626f621d794692c1b"
      id = "ea883f25-0e9b-5617-b05e-191a4a5c5a52"
   strings:
      $x1 = "<font size=4>Cleanup Shell</font></a>';" ascii fullword
      $x2 = "$(sh /tmp/.scr)"
      $x3 = "@system('sudo /usr/local/bin/admin.pl --mount_cifs=" ascii
      
      $s1 = "target=\\\"_blank\\\">Download</a></td>\";" ascii
      $s2 = ",PASSWORD 1>/dev/null 2>/dev/null');" ascii
      $s3 = ",base64_decode('" ascii
      $s4 = "include \"remote.inc\";" ascii
      $s5 = "@system('sudo /usr/local" ascii
   condition:
      uint16(0) == 0x3f3c and
      filesize < 9KB and
      ( 1 of ($x*) or 2 of them ) or 3 of them
}
