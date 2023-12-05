
rule SUSP_PS1_JAB_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious UTF16 and Base64 encoded PowerShell code that starts with a $ sign and a single char variable"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-10"
      score= 70
      id = "9ecca7d9-3b63-5615-a223-5efa1c53510e"
   strings:
      /* 
         with spaces : $c = $ 
         https://gchq.github.io/CyberChef/#recipe=Fork('%5C%5Cn','%5C%5Cn',false)Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')Encode_text('UTF-16LE%20(1200)'/disabled)To_Hex('Space',0)&input=JHAgPSAkRW52OnRlbQokeCA9ICRteXZhcjsKJHggPSBJbnZva2Ut
      */
      /* ASCII */ 
      $xc1 = { 4a 41 42 ?? 41 43 41 41 50 51 41 67 41 }
      /* UTF-16 encoded */
      $xc2 = { 4a 00 41 00 42 00 ?? 00 41 00 43 00 41 00 41 00 50 00 51 00 41 00 67 00 41 }
      /* 
         without spaces : $c=$ 
         https://gchq.github.io/CyberChef/#recipe=Fork('%5C%5Cn','%5C%5Cn',false)Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')Encode_text('UTF-16LE%20(1200)'/disabled)To_Hex('Space',0)&input=JHA9JEVudjp0ZW0KJHg9JG15dmFyOwokeD1JbnZva2Ut
      */
      /* ASCII */ 
      $xc3 = { 4a 41 42 ?? 41 44 30 41 }
      /* UTF-16 encoded */
      $xc4 = { 4a 00 41 00 42 00 ?? 00 41 00 44 00 30 00 41 }
   condition:
      filesize < 30MB and 1 of them
}
