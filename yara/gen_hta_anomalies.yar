/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-20
   Identifier: HTA Anomalies
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule HTA_with_WScript_Shell {
   meta:
      description = "Detects WScript Shell in HTA"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 80
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
      id = "2faf74b1-c19c-53f0-ad08-be9caf5640bc"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
      $s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii
   condition:
      all of them
}

rule HTA_Embedded {
   meta:
      description = "Detects an embedded HTA file"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 50
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
      id = "04d4c718-9dd6-5528-8712-61c9f2a16139"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
   condition:
      $s1 and not $s1 in (0..50000)
}
