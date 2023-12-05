
rule MAL_JS_EFile_Apr23_1 {
   meta:
      description = "Detects JavaScript malware used in eFile compromise"
      author = "Florian Roth"
      score = 75
      reference = "https://twitter.com/Ax_Sharma/status/1643178696084271104/photo/1"
      date = "2023-04-06"
      id = "ba7a8b2c-789c-5bc5-be53-f2b92c7039e1"
   strings:
      $s1 = "let payload_chrome = "
      $s2 = "else if (agent.indexOf(\"firefox"
   condition:
      all of them
}


rule MAL_PHP_EFile_Apr23_1 {
   meta:
      description = "Detects malware "
      author = "Florian Roth"
      reference = "https://twitter.com/malwrhunterteam/status/1642988428080865281?s=12&t=C0_T_re0wRP_NfKa27Xw9w"
      date = "2023-04-06"
      score = 75
      id = "d663b38e-b082-5cf7-9853-f4685bf3a87b"
   strings:
      $s1 = "mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )" ascii
      $s2 = "C:\\\\ProgramData\\\\Browsers" ascii fullword
      $s3 = "curl_https($api_url." ascii
   condition:
      all of them
}
