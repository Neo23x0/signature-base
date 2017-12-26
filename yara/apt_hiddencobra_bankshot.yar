/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-26
   Identifier: Hidden Cobra - BANKSHOT
   Reference: https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity
*/

/* Rule Set ----------------------------------------------------------------- */

rule HiddenCobra_BANKSHOT_Gen {
   meta:
      description = "Detects Hidden Cobra BANKSHOT trojan"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
      date = "2017-12-26"
      hash1 = "89775a2fbb361d6507de6810d2ca71711d5103b113179f1e1411ccf75e6fc486"
      hash2 = "8b2d084a8bb165b236d3e5436d6cb6fa1fda6431f99c4f34973dc735b4f2d247"
      hash3 = "b766ee0f46c92a746f6db3773735ee245f36c1849de985bbc3a37b15f7187f24"
      hash4 = "daf5facbd67f949981f8388a6ca38828de2300cb702ad530e005430782802b75"
      hash5 = "ef6f8b43caa25c5f9c7749e52c8ab61e8aec8053b9f073edeca4b35312a0a699"
      hash6 = "d900ee8a499e288a11f1c75e151569b518864e14c58cc72c47f95309956b3eff"
      hash7 = "ec44ecd57401b3c78d849115f08ff046011b6eb933898203b7641942d4ee3af9"
      hash8 = "3e6d575b327a1474f4767803f94799140e16a729e7d00f1bea40cd6174d8a8a6"
      hash9 = "6db37a52517653afe608fd84cc57a2d12c4598c36f521f503fd8413cbef9adca"
   strings:
      $s1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" fullword wide
      $s2 = "rHTTP/1.1 200 Connection established" fullword wide
      $s3 = "Proxy-Connection: keep-alive" fullword wide
      $s4 = "\\msncf.dat" fullword wide
      $s5 = "msvcru32.bat" fullword ascii
      $s6 = "reg delete \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"%s\" /f" fullword ascii
      $s7 = "MXINFO.DLL" fullword ascii
      $s8 = "usrvc32.bat" fullword ascii
      $s9 = "ping -n 1 127.0.0.1" fullword ascii
      $s10 = "%sd.e%sc \"%s > %s 2>&1\"" ascii fullword
      $s11 = "DWS*.tmp" ascii fullword
      $s12 = "CS*.tmp" fullword wide
      $s13 = "WM*.tmp" fullword wide

      $x1 = "CgpaipIddwspwe32Hnaehsdi" fullword ascii
      $x2 = "RpiPmtiCdopIsgpao" fullword ascii
      $x3 = "RpiLtnodlhOtgpcidgyA" fullword ascii
      $x4 = "LatiQdgHtnrwpDbupci" fullword ascii
      $x5 = "vchost.exe" fullword ascii
      $x6 = "\\system32\\msncf.dat" fullword ascii
      $x7 = "GprthipgHpgktcpCigwSanowpgA" fullword ascii

      $a1 = "live.dropbox.com" fullword ascii
      $a2 = "tatadocomo.yahoo.com" fullword ascii
      $a3 = "widgets.twimg.com" fullword ascii
      $a4 = "history.paypal.com" fullword ascii
      $a5 = "www.bitcoin.org" fullword ascii
      $a6 = "web.whatsapp.com" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and (
         1 of ($x*) or
         2 of ($s*) or
         4 of ($a*)
      )
}

/* US CERT Rule */

rule Unauthorized_Proxy_Server_RAT {
   meta:
      author = "US-CERT Code Analysis Team"
      reference = "https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity"
      hash1 = "C74E289AD927E81D2A1A56BC73E394AB"
      hash2 = "2950E3741D7AF69E0CA0C5013ABC4209"
      desscription = "Detects Proxy Server RAT"
   strings:
      $s0 = {8A043132C288043125FF00000003C299F73D40404900A14440490003D0413BCF72DE5E5FC3}
      $s1 = {8A04318844241432C28804318B44241425FF00000003C299F73D40404900A14440490003D0413BCF72D65E5FC3}
      $s2 = {8A04318844241432C28804318B44241425FF00000003C299F73D5C394100A16039410003D0413BCF72D65E5FC3}
      $s3 = {8A043132C288043125FF00000003C299F73D5C394100A16039410003D0413BCF72DE5E5FC3}
      $s4 = {B91A7900008A140780F29A8810404975F4}
      $s5 = {399FE192769F839DCE9F2A9D2C9EAD9CEB9FD19CA59F7E9F539CEF9F029F969C6C9E5C9D949FC99F}
      $s6 = {8A04318844241432C28804318B44241425FF00000003C299F73D40600910A14460091003D0413BCF72D65E5FC3}
      $s7 = {3C5C75208A41014184C074183C72740C3C7474083C6274043C2275088A41014184C075DC}
      $s8 = {8B063D9534120077353D59341200722E668B4604663DE8037F24}
      $s9 = {8BC88B74241CC1E1052BC88B7C2418C1E1048B5C241403C88D04888B4C242083F9018944240C7523}
      $s10 = {8B063D9034120077353D59341200722E668B4604663DE8037F246685C0}
      $s11 = {30110FB60148FFC102C20FBEC09941F7F94103D249FFC875E7}
      $s12 = {448BE8B84FECC44E41F7EDC1FA038BCAC1E91F03D16BD21A442BEA4183C541}
      $s13 = {8A0A80F9627C2380F9797F1E80F9647C0A80F96D7F0580C10BEB0D80F96F7C0A80F9787F05}
   condition:
      any of them
}
