rule Base64_PS1_Shellcode {
   meta:
      description = "Detects Base64 encoded PS1 Shellcode"
      author = "Nick Carr, David Ledbetter"
      reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
      date = "2018-11-14"
      score = 65
   strings:
      $substring = "AAAAYInlM"
      $pattern1 = "/OiCAAAAYInlM"
      $pattern2 = "/OiJAAAAYInlM"
   condition:
      $substring and 1 of ($p*)
}
