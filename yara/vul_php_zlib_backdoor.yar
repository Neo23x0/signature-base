
rule VULN_PHP_Hack_Backdoored_Zlib_Zerodium_Mar21_1 {
   meta:
      description = "Detects backdoored PHP zlib version"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/news/security/phps-git-server-hacked-to-add-backdoors-to-php-source-code/"
      date = "2021-03-29"
   strings:
      $x1 = "REMOVETHIS: sold to zerodium, mid 2017" fullword ascii
      $x2 = "HTTP_USER_AGENTT" ascii fullword
   condition:
      filesize < 3000KB and
      all of them
}
