/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-05-01
   Identifier: APT10 / Hogfish Report
   Reference: https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule MAL_Hogfish_Report_Related_Sample {
   meta:
      description = "Detects APT10 / Hogfish related samples"
      author = "Florian Roth"
      reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
      date = "2018-05-01"
      hash1 = "f9acc706d7bec10f88f9cfbbdf80df0d85331bd4c3c0188e4d002d6929fe4eac"
      hash2 = "7188f76ca5fbc6e57d23ba97655b293d5356933e2ab5261e423b3f205fe305ee"
      hash3 = "4de5a22cd798950a69318fdcc1ec59e9a456b4e572c2d3ac4788ee96a4070262"
   strings:
      $s1 = "R=user32.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "efad9ff8c0d2a6419bf1dd970bcd806d" or
         1 of them
      )
}

rule MAL_RedLeaves_Apr18_1 {
   meta:
      description = "Detects RedLeaves malware"
      author = "Florian Roth"
      reference = "https://www.accenture.com/t20180423T055005Z__w__/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf"
      date = "2018-05-01"
      hash1 = "f6449e255bc1a9d4a02391be35d0dd37def19b7e20cfcc274427a0b39cb21b7b"
      hash2 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"
      hash3 = "d956e2ff1b22ccee2c5d9819128103d4c31ecefde3ce463a6dea19ecaaf418a1"
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and (
         pe.imphash() == "7a861cd9c495e1d950a43cb708a22985" or
         pe.imphash() == "566a7a4ef613a797389b570f8b4f79df"
      )
}
