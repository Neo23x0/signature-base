/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-03-06
   Identifier: TSCookie RAT
   Reference: http://blog.jpcert.or.jp/2018/03/malware-tscooki-7aa0.html
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule TSCookie_RAT {
   meta:
      description = "Detects TSCookie RAT"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.jpcert.or.jp/2018/03/malware-tscooki-7aa0.html"
      date = "2018-03-06"
      hash1 = "2bd13d63797864a70b775bd1994016f5052dc8fd1fd83ce1c13234b5d304330d"
      id = "a2b6c598-4498-5c0a-9257-b0bf6cd28de9"
   strings:
      $x1 = "[-] DecryptPassword_Outlook failed(err=%d)" fullword ascii
      $x2 = "----------------------- Firefox Passwords ------------------" fullword ascii
      $x3 = "--------------- Outlook Passwords ------------------" fullword ascii
      $x4 = "----------------------- IE Passwords ------------------" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         ( pe.exports("DoWork") and pe.exports("PrintF") ) or
         1 of them
      )
}
