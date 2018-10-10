/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-22
   Identifier: TurlaMosquito
   Reference: https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule TurlaMosquito_Mal_1 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b295032919143f5b6b3c87ad22bcf8b55ecc9244aa9f6f88fc28f36f5aa2925e"
   strings:
      $s1 = "Pipetp" fullword ascii
      $s2 = "EStOpnabn" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and (
        pe.imphash() == "169d4237c79549303cca870592278f42" or
        all of them
      )
}

rule TurlaMosquito_Mal_2 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "68c6e9dea81f082601ae5afc41870cea3f71b22bfc19bcfbc61d84786e481cb4"
      hash2 = "05254971fe3e1ca448844f8cfcfb2b0de27e48abd45ea2a3df897074a419a3f4"
   strings:
      $s1 = ".?AVFileNameParseException@ExecuteFile@@" fullword ascii
      $s3 = "no_address" fullword wide
      $s6 = "SRRRQP" fullword ascii
      $s7 = "QWVPQQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and (
        pe.imphash() == "cd918073f209c5da7a16b6c125d73746" or
        all of them
      )
}

rule TurlaMosquito_Mal_3 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "443cd03b37fca8a5df1bbaa6320649b441ca50d1c1fcc4f5a7b94b95040c73d1"
   strings:
      $x1 = "InstructionerDLL.dll" fullword ascii

      $s1 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
      $s2 = "/scripts/m/query.php?id=" fullword wide
      $s3 = "SELECT * FROM AntiVirusProduct" fullword ascii
      $s4 = "Microsoft Update" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "88488fe0b8bcd6e379dea6433bb5d7d8" or
         ( pe.exports("InstallRoutineW") and pe.exports("StartRoutine") ) or
         $x1 or
         3 of them
      )
}

rule TurlaMosquito_Mal_4 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b362b235539b762734a1833c7e6c366c1b46474f05dc17b3a631b3bff95a5eec"
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "17b328245e2874a76c2f46f9a92c3bad"
}

rule TurlaMosquito_Mal_5 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "26a1a42bc74e14887616f9d6048c17b1b4231466716a6426e7162426e1a08030"
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and pe.imphash() == "ac40cf7479f53a4754ac6481a4f24e57"
}

rule TurlaMosquito_Mal_6 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "b79cdf929d4a340bdd5f29b3aeccd3c65e39540d4529b64e50ebeacd9cdee5e9"
   strings:
      $a1 = "/scripts/m/query.php?id=" fullword wide
      $a2 = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36" fullword wide
      $a3 = "GetUserNameW fails" fullword wide

      $s1 = "QVSWQQ" fullword ascii
      $s2 = "SRRRQP" fullword ascii
      $s3 = "QSVVQQ" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         2 of ($a*) or
         4 of them
      )
}

rule TurlaMosquito_Mal_7 {
   meta:
      description = "Detects malware sample from Turla Mosquito report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
      date = "2018-02-22"
      hash1 = "e7fd14ca45818044690ca67f201cc8cfb916ccc941a105927fc4c932c72b425d"
   strings:
      $x1 = "Logger32.dll" fullword ascii
      $s6 = "lManager::Execute : CPalExceptio" fullword wide
      $s19 = "CCommandSender::operator(" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
        pe.imphash() == "073235ae6dfbb1bf5db68a039a7b7726" or
        3 of them
      )
}
