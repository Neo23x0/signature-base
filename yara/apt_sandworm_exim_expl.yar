
rule APT_Sandworm_Keywords_May20_1 {
   meta:
      description = "Detects commands used by Sandworm group to exploit critical vulernability CVE-2019-10149 in Exim"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2020/May/28/2002306626/-1/-1/0/CSA%20Sandworm%20Actors%20Exploiting%20Vulnerability%20in%20Exim%20Transfer%20Agent%2020200528.pdf"
      date = "2020-05-28"
   strings:
      $x1 = "MAIL FROM:<$(run("
      $x2 = "exec\\x20\\x2Fusr\\x2Fbin\\x2Fwget\\x20\\x2DO\\x20\\x2D\\x20http"
   condition:
      filesize < 8000KB and
      1 of them
}
