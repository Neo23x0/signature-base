
import "pe"

rule MAL_Nitol_Malware_Jan19_1 {
   meta:
      description = "Detects Nitol Malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/shotgunner101/status/1084602413691166721"
      date = "2019-01-14"
      hash1 = "fe65f6a79528802cb61effc064476f7b48233fb0f245ddb7de5b7cc8bb45362e"
      id = "5b9968a8-31ba-593b-9e01-b69a4e31fe65"
   strings:
      $xc1 = { 00 25 75 20 25 73 00 00 00 30 2E 30 2E 30 2E 30
               00 25 75 20 4D 42 00 00 00 25 64 2A 25 75 25 73
               00 7E 4D 48 7A }
      $xc2 = "GET ^&&%$%$^" ascii

      $n1 = ".htmGET " ascii

      $s1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $s2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $s3 = "User-Agent:Mozilla/5.0 (X11; U; Linux i686; en-US; re:1.4.0) Gecko/20080808 Firefox/%d.0" fullword ascii
      $s4 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "286870a926664a5129b8b68ed0d4a8eb" or
         1 of ($x*) or
         #n1 > 4 or
         4 of them
      )
}
