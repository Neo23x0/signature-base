import "pe"

rule MAL_Floxif_Generic {
   meta:
      description = "Detects Floxif Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11"
      score = 80
      hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.imphash() == "2f4ddcfebbcad3bacadc879747151f6f" or
         pe.exports("FloodFix") or pe.exports("FloodFix2")
      )
}


rule MAL_CN_FlyStudio_May18_1 {
   meta:
      description = "Detects malware / hacktool detected in May 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-11"
      hash1 = "b85147366890598518d4f277d44506eef871fd7fc6050d8f8e68889cae066d9e"
   strings:
      $s1 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
      $s2 = "www.cfyhack.cn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and (
         pe.imphash() == "65ae5cf17140aeaf91e3e9911da0ee3e" or
         1 of them
      )
}
