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
      author = "Florian Roth"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 80
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
      $s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii
   condition:
      all of them
}

rule HTA_Embedded {
   meta:
      description = "Detects an embedded HTA file"
      author = "Florian Roth"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 50
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
   condition:
      $s1 and not $s1 in (0..50000)
}
