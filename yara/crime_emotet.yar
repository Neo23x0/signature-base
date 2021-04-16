
rule MAL_Emotet_JS_Dropper_Oct19_1 {
   meta:
      description = "Detects Emotet JS dropper"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/aaa75105-dc85-48ca-9732-085b2ceeb6eb/"
      date = "2019-10-03"
      hash1 = "38295d728522426672b9497f63b72066e811f5b53a14fb4c4ffc23d4efbbca4a"
      hash2 = "9bc004a53816a5b46bfb08e819ac1cf32c3bdc556a87a58cbada416c10423573"
   strings:
      $xc1 = { FF FE 76 00 61 00 72 00 20 00 61 00 3D 00 5B 00
               27 00 }
   condition:
      uint32(0) == 0x0076feff and filesize <= 700KB and $xc1 at 0
}

import "pe"

rule MAL_Emotet_Jan20_1 {
   meta:
      description = "Detects Emotet malware"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/5e81638e-df2e-4a5b-9e45-b07c38d53929/"
      date = "2020-01-29"
      hash1 = "e7c22ccdb1103ee6bd15c528270f56913bb2f47345b360802b74084563f1b73d"
   strings:
      $op0 = { 74 60 8d 34 18 eb 54 03 c3 50 ff 15 18 08 41 00 }
      $op1 = { 03 fe 66 39 07 0f 85 2a ff ff ff 8b 4d f0 6a 20 }
      $op2 = { 8b 7d fc 0f 85 49 ff ff ff 85 db 0f 84 d1 }
   condition:
      uint16(0) == 0x5a4d and filesize <= 200KB and (
         pe.imphash() == "009889c73bd2e55113bf6dfa5f395e0d" or
         1 of them
      )
}

rule MAL_Emotet_BKA_Quarantine_Apr21 {
   meta:
      author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
      reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
      descripton = "The modified emotet binary replaces the original emotet on the system of the victim. The original emotet is copied to a quarantine for evidence-preservation."
      note = "The quarantine folder depends on the scope of the initial emotet infection (user or administrator). It is the temporary folder as returned by GetTempPathW under a filename starting with UDP as returned by GetTempFileNameW. To prevent accidental reinfection by a user, the quarantined emotet is encrypted using RC4 and a 0x20 bytes long key found at the start of the quarantined file (see $key)."
      sharing = "TLP:WHITE"
      date = "2021-03-23"
   strings:
      $key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }
   condition:
      $key at 0
}

rule MAL_Emotet_BKA_Cleanup_Apr21 {
   meta:
      author = "press inquiries <info@bka.de>, technical contact <info@mha.bka.de>"
      reference = "https://www.bka.de/DE/IhreSicherheit/RichtigesVerhalten/StraftatenImInternet/FAQ/FAQ_node.html"
      descripton = "This rule targets a modified emotet binary deployed by the Bundeskriminalamt on the 26th of January 2021."
      note = "The binary will replace the original emotet by copying it to a quarantine. It also contains a routine to perform a self-deinstallation on the 25th of April 2021. The three-month timeframe between rollout and self-deinstallation was chosen primarily for evidence purposes as well as to allow remediation."
      sharing = "TLP:WHITE"
      date = "2021-03-23"
   strings:
      $key = { c3 da da 19 63 45 2c 86 77 3b e9 fd 24 64 fb b8 07 fe 12 d0 2a 48 13 38 48 68 e8 ae 91 3c ed 82 }
   condition:
      filesize > 300KB and
      filesize < 700KB and
      uint16(0) == 0x5A4D and
      $key
}

