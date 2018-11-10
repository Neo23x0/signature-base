/*
   LICENSE
   Copyright (C) 2015 JPCERT Coordination Center. All Rights Reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following acknowledgments and disclaimers.
   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following acknowledgments and disclaimers
      in the documentation and/or other materials provided with the distribution.
   3. Products derived from this software may not include "JPCERT Coordination
      Center" in the name of such derived product, nor shall "JPCERT
      Coordination Center"  be used to endorse or promote products derived
      from this software without prior written permission. For written
      permission, please contact pr@jpcert.or.jp.

   ACKNOWLEDGMENTS AND DISCLAIMERS
   Copyright (C) 2015 JPCERT Coordination Center

   This software is based upon work funded and supported by the Ministry of
   Economy, Trade and Industry.

   Any opinions, findings and conclusions or recommendations expressed in this
   software are those of the author(s) and do not necessarily reflect the views
   of the Ministry of Economy, Trade and Industry.

   NO WARRANTY. THIS JPCERT COORDINATION CENTER SOFTWARE IS FURNISHED ON
   AN "AS-IS" BASIS. JPCERT COORDINATION CENTER MAKES NO WARRANTIES OF
   ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT
   NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
   EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE SOFTWARE. JPCERT
   COORDINATION CENTER DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH
   RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   This software has been approved for public release and unlimited distribution.
*/

rule APT_CobaltStrike_Beacon_Indicator {
   meta:
      description = "Detects CobaltStrike beacons"
      author = "JPCERT"
      reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
      date = "2018-11-09"
   strings:
      $v1 = { 73 70 72 6E 67 00 }
      $v2 = { 69 69 69 69 69 69 69 69 }
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
}
