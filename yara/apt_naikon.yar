
rule MAL_Backdoor_Naikon_APT_Sample1 {
   meta:
      description = "Detects backdoors related to the Naikon APT"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/7vHyvh"
      date = "2015-05-14"
		modified = "2023-01-06"
      hash = "d5716c80cba8554eb79eecfb4aa3d99faf0435a1833ec5ef51f528146c758eba"
      hash = "f5ab8e49c0778fa208baad660fe4fa40fc8a114f5f71614afbd6dcc09625cb96"
      id = "ba79285b-7c7f-5b19-837e-6696e50a2866"
   strings:
      $x0 = "GET http://%s:%d/aspxabcdef.asp?%s HTTP/1.1" fullword ascii
      $x1 = "POST http://%s:%d/aspxabcdefg.asp?%s HTTP/1.1" fullword ascii
      $x2 = "greensky27.vicp.net" fullword ascii
      $x3 = "\\tempvxd.vxd.dll" wide
      $x5 = "otna.vicp.net" fullword ascii

      $s1 = "User-Agent: webclient" fullword ascii
      $s2 = "\\User.ini" ascii
      $s3 = "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-EN; rv:1.7.12) Gecko/200" ascii
      $s4 = "\\UserProfile.dll" wide
      $s5 = "Connection:Keep-Alive: %d" fullword ascii
      $s6 = "Referer: http://%s:%d/" ascii
      $s7 = "%s %s %s %d %d %d " fullword ascii
      $s8 = "%s--%s" fullword wide
      $s9 = "Run File Success!" fullword wide
      $s10 = "DRIVE_REMOTE" fullword wide
      $s11 = "ProxyEnable" fullword wide
      $s12 = "\\cmd.exe" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      (
         1 of ($x*) or 7 of ($s*)
      )
}