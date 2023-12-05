/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-06
   Identifier: GoldenEye Ransomware
*/

/* Rule Set ----------------------------------------------------------------- */

rule GoldenEye_Ransomware_XLS {
   meta:
      description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
      id = "6eafcc35-56ef-534f-884a-0bb47c27c274"
   strings:
      $x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
      $x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 1 of them )
}

rule GoldenEyeRansomware_Dropper_MalformedZoomit {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/jp2SkT"
      date = "2016-12-06"
      hash1 = "b5ef16922e2c76b09edd71471dd837e89811c5e658406a8495c1364d0d9dc690"
      id = "6ebf2d13-7d58-5a1b-a836-66d533f408e8"
   strings:
      $s1 = "ZoomIt - Sysinternals: www.sysinternals.com" fullword ascii
      $n1 = "Mark Russinovich" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 800KB and $s1 and not $n1 )
}
