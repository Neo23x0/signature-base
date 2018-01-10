/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-01-09
   Identifier: NK Miner Malware
   Reference: https://goo.gl/PChE1z
*/

/* Rule Set ----------------------------------------------------------------- */

rule NK_Miner_Malware_Jan18_1 {
   meta:
      description = "Detects Noth Korean Monero Miner mentioned in AlienVault report"
      author = "Florian Roth (original rule by Chris Doman)"
      reference = "https://goo.gl/PChE1z"
      date = "2018-01-09"
      hash1 = "0024e32c0199ded445c0b968601f21cc92fc0c534d2642f2dd64c1c978ff01f3"
      hash2 = "42300b6a09f183ae167d7a11d9c6df21d022a5f02df346350d3d875d557d3b76"
   strings:
      $x0 = "c:\\users\\jawhar\\documents\\" ascii
      $x1 = "C:\\Users\\Jawhar\\documents\\" ascii
      $x2 = "The number of processors on this computer is {0}." fullword wide
      $x3 = { 00 00 1F 43 00 3A 00 5C 00 4E 00 65 00 77 00 44
              00 69 00 72 00 65 00 63 00 74 00 6F 00 72 00 79
              00 00 }
      $x4 = "Le fichier Hello txt n'existe pas" fullword wide
      $x5 = "C:\\NewDirectory2\\info2" fullword wide

      /* Incorported from Chris Doman's rule - https://goo.gl/PChE1z*/
      $a = "82e999fb-a6e0-4094-aa1f-1a306069d1a5" ascii
      $b = "4JUdGzvrMFDWrUUwY3toJATSeNwjn54LkCnKBPRzDuhzi5vSepHfUckJNxRL2gjkNrSqtCoRUrEDAgRwsQvVCjZbRy5YeFCqgoUMnzumvS" ascii
      $c = "barjuok.ryongnamsan.edu.kp" wide ascii
      $d = "C:\\SoftwaresInstall\\soft" wide ascii
      $e = "C:\\Windows\\Sys64\\intelservice.exe" wide ascii
      $f = "C:\\Windows\\Sys64\\updater.exe" wide ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and 1 of them
}
