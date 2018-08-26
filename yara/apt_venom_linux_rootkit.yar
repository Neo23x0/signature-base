/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-10
   Identifier: Venom Rootkit
*/

/* Rule Set ----------------------------------------------------------------- */

rule Venom_Rootkit {
   meta:
      description = "Venom Linux Rootkit"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://security.web.cern.ch/security/venom.shtml"
      date = "2017-01-12"
   strings:
      $s1 = "%%VENOM%CTRL%MODE%%" ascii fullword
      $s2 = "%%VENOM%OK%OK%%" ascii fullword
      $s3 = "%%VENOM%WIN%WN%%" ascii fullword
      $s4 = "%%VENOM%AUTHENTICATE%%" ascii fullword
      $s5 = ". entering interactive shell" ascii fullword
      $s6 = ". processing ltun request" ascii fullword
      $s7 = ". processing rtun request" ascii fullword
      $s8 = ". processing get request" ascii fullword
      $s9 = ". processing put request" ascii fullword
      $s10 = "venom by mouzone" ascii fullword
      $s11 = "justCANTbeSTOPPED" ascii fullword
   condition:
      filesize < 4000KB and 2 of them
}
