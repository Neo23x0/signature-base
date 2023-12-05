/*
Copyright 2021 by ditekSHen (https://github.com/ditekshen/detection).

The 2-Clause BSD License

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

rule SUSP_INDICATOR_RTF_MalVer_Objects { //phns-1666275333
   meta:
      description = "Detects RTF documents with non-standard version and embedding one of the object mostly observed in exploit (e.g. CVE-2017-11882) documents."
      author = "ditekSHen"
      reference = "https://github.com/ditekshen/detection"
      date = "2022-10-20"
      score = 65
      hash1 = "43812ca7f583e40b3e3e92ae90a7e935c87108fa863702aa9623c6b7dc3697a2"
      hash2 = "a31da6c6a8a340901f764586a28bd5f11f6d2a60a38bf60acd844c906a0d44b1"
      id = "2d9d80e0-473e-5aac-a576-8f0002e120e2"
   strings:
      // Embedded Objects
      $obj1 = "\\objhtml" ascii
      $obj2 = "\\objdata" ascii
      $obj3 = "\\objupdate" ascii
      $obj4 = "\\objemb" ascii
      $obj5 = "\\objautlink" ascii
      $obj6 = "\\objlink" ascii
   condition:
      uint32(0) == 0x74725c7b and (
         // missing 'f' after '{\rt' and missing '1' (version) after 'rtf' and no char-set set ('\' missing at pos 6)
         // https://www.biblioscape.com/rtf15_spec.htm#Heading6
         (not uint8(4) == 0x66 or not uint8(5) == 0x31 or not uint8(6) == 0x5c) 
         and 1 of ($obj*)
      )
}