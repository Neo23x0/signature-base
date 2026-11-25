rule MAL_APT_NK_JS_PolinRider_Loader_A10_Nov26 {
   meta:
      description = "Detects the PolinRider loader of strain A10 (global.i = 'A10-...'), appended after hundreds of spaces to config files, extensionless 'init' and '.vscode/eslint' files or fake font files in compromised repos. The loader finds its C2 in the recipient address of an Ethereum transaction from a fixed sender wallet (NullReceiver) and fetches /0x/cls and /0x/ls. Covers both packagings seen in November 2026: javascript-obfuscator output and base64 chunks passed to atob and eval"
      author = "n4uu"
      reference = "https://www.sonatype.com/blog/polinrider-loader-reappears-in-hijacked-npm-packages"
      date = "2026-11-12"
      score = 80
      hash1 = "a9f67e794eb6f4428ac64a331a747bffb3502c5ff0a08280288b4d20307e3980"
      hash2 = "ca92a5d5286319008106d15de85dbb58d9160c6b8f02375dedbbf9be097427d6"
      hash3 = "948f8acaf5783c4ef93c7884d643db248300b05780562a8e0f9668e260bd37b9"
      id = "eaf56473-e229-4b82-b5dd-97687904ccd7"
   strings:
      // strain tag after the space padding that pushes the loader off screen
      $tag = /global\.i = 'A[0-9]{1,2}-[*0-9_-]{1,24}';/ ascii
      $pad = /[ ]{32}global\.i = 'A[0-9]/ ascii

      // javascript-obfuscator build: pieces of the split string array
      $a1 = "42Cf3c8bCE" ascii   // slice of the hard-coded sender wallet
      $a2 = ":443/0x/cl" ascii
      $a3 = "eth_getTra" ascii
      $a4 = "nsactionCo" ascii

      // base64 build: chunks joined, decoded with atob and passed to eval
      $b1 = "Z2xvYmFsWydyJ10gPSByZXF1aXJlOw0K" ascii   // global['r'] = require;\r\n
      $b2 = ".join('');var _0x" ascii
      $b3 = "=atob(_0x" ascii
      $b4 = ";eval(_0x" ascii

      // decoded loader
      $c1 = "0x1eEf0849EDa15d87f64e51C73C8442Cf3c8bCEF3" ascii nocase
      $c2 = "/0x/cls" ascii
      $c3 = "X-Payload-B64" ascii
   condition:
      filesize < 500KB
      and (
         ( ($tag or $pad) and ( 3 of ($a*) or 3 of ($b*) ) )
         or ( $c1 and 1 of ($c2, $c3) )
      )
}
