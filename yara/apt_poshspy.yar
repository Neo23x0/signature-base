/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-15
   Identifier: APT29 POSHSPY
   Reference: https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule POSHSPY_Malware {
   meta:
      description = "Detects"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html"
      date = "2017-07-15"
   strings:
      $x1 = "function sWP($cN, $pN, $aK, $aI)" fullword ascii
      $x2 = "$aeK = [byte[]] (0x69, 0x87, 0x0b, 0xf2" ascii
      $x3 = "(('variant', 'excretions', 'accumulators', 'winslow', 'whistleable', 'len',"
      $x4 = "$cPairKey = \"BwIAAACkAABSU0EyAAQAAAEAA"
      $x5 = "$exeRes = exePldRoutine"
      $x6 = "ZgB1AG4AYwB0AGkAbwBuACAAcAB1AHIAZgBDAHIA"
   condition:
      1 of them
}
