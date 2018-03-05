rule gen_python_reverse_shell
{
   meta:
      description = "Python Base64 encoded reverse shell"
      author = "John Lambert @JohnLaTwC"
      reference = "https://www.virustotal.com/en/file/9ec5102bcbabc45f2aa7775464f33019cfbe9d766b1332ee675957c923a17efd/analysis/"
      date = "2018-02-24"
      hash1 = "9ec5102bcbabc45f2aa7775464f33019cfbe9d766b1332ee675957c923a17efd"
      hash2 = "bfb5c622a3352bb71b86df81c45ccefaa68b9f7cc0a3577e8013aad951308f12"
   strings:
      $h1 = "import base64" fullword ascii

      $s1 = "b64decode" fullword ascii
      $s2 = "lambda" fullword ascii
      $s3 = "version_info" fullword ascii

      //Base64 encoded versions of these strings
      // socket.SOCK_STREAM
      $enc_x0 = /(AG8AYwBrAGUAdAAuAFMATwBDAEsAXwBTAFQAUgBFAEEATQ|b2NrZXQuU09DS19TVFJFQU|c29ja2V0LlNPQ0tfU1RSRUFN|cwBvAGMAawBlAHQALgBTAE8AQwBLAF8AUwBUAFIARQBBAE0A|MAbwBjAGsAZQB0AC4AUwBPAEMASwBfAFMAVABSAEUAQQBNA|NvY2tldC5TT0NLX1NUUkVBT)/ ascii

      //.connect((
      $enc_x1 = /(4AYwBvAG4AbgBlAGMAdAAoACgA|5jb25uZWN0KC|AGMAbwBuAG4AZQBjAHQAKAAoA|LgBjAG8AbgBuAGUAYwB0ACgAKA|LmNvbm5lY3QoK|Y29ubmVjdCgo)/

      //time.sleep
      $enc_x2 = /(AGkAbQBlAC4AcwBsAGUAZQBwA|aW1lLnNsZWVw|dABpAG0AZQAuAHMAbABlAGUAcA|dGltZS5zbGVlc|QAaQBtAGUALgBzAGwAZQBlAHAA|RpbWUuc2xlZX)/

      //.recv
      $enc_x3 = /(4AcgBlAGMAdg|5yZWN2|AHIAZQBjAHYA|cmVjd|LgByAGUAYwB2A|LnJlY3)/
   condition:
      uint32be(0) == 0x696d706f
      and $h1 at 0
      and filesize < 40KB
      and all of ($s*)
      and all of ($enc_x*)
}
