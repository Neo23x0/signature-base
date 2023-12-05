/*
import "pe"

rule SUSP_Solarwinds_SUNBURST_Revoked_Cert {
   meta:
      description = "Detects executables signed with a compromised certificate after 2019 (it doesn't mean that the "
      date = "2020-12-14"
      reference = "https://github.com/fireeye/sunburst_countermeasures/pull/3#issuecomment-747156202"
      score = 50
   condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "Symantec Class 3 SHA256 Code Signing CA" and
         pe.signatures[i].serial == "0f:e9:73:75:20:22:a6:06:ad:f2:a3:6e:34:5d:c0:ed" and
         // valid after Tuesday, January 1, 2019 0:00:00
         pe.signatures[i].not_before > 1546300800
      )
}
*/

rule LOG_APT_WEBSHELL_Solarwinds_SUNBURST_Report_Webshell_Dec20_2 {
   meta:
      description = "Detects webshell access mentioned in FireEye's SUNBURST report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guidepointsecurity.com/supernova-solarwinds-net-webshell-analysis/"
      date = "2020-12-21"
      id = "fb86164d-13de-5357-8f52-c597b51127ff"
   strings:
      $xr1 = /logoimagehandler.ashx[^\n\s]{1,400}clazz=/ ascii wide
   condition:
      $xr1
}
