/* Threat Hunting Rule - note the score of 40 > Notice */

rule SUSP_RAR_Single_Doc_File {
   meta:
      description = "Detects suspicious RAR files that contain nothing but a single .doc file"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-07-11"
      score = 40
      hash1 = "51a568ac3ceb6bc4a4a123af9ca383a32bac0f630b17a1cc99e45ff8002727b1"
      hash2 = "f9eddbebf9c41089d7507291adbaac8a4bcebffcd960f838d8a9648194d38a4a"
   strings:
      $s1 = ".doc"
   condition:
      uint16(0) == 0x6152 and
      filesize < 4000KB and
      $s1 at (
         uint16(5) +  // header size
         uint16(uint16(5)+5) +  // rar header size
         uint16(uint16(5) + uint16(uint16(5)+5) + 5)  // rar block size
         - 9  // offset
      ) and (
         // single rar block for a single doc file
         uint16(5) +  // header size
         uint16(uint16(5)+5) +  // rar header size
         uint16(uint16(5) + uint16(uint16(5)+5) + 5) +  // rar block size
         uint32(uint16(5) + uint16(uint16(5)+5) + 7)  // raw data size
         > filesize-8
      )
}
