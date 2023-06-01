
rule WEBSHELL_ASPX_MOVEit_Jun23_1 {
   meta:
      description = "Detects ASPX web shells as being used in MOVEit Transfer exploitation"
      author = "Florian Roth"
      reference = "https://www.rapid7.com/blog/post/2023/06/01/rapid7-observed-exploitation-of-critical-moveit-transfer-vulnerability/"
      date = "2023-06-01"
      score = 85
      hash1 = "2413b5d0750c23b07999ec33a5b4930be224b661aaf290a0118db803f31acbc5"
      hash2 = "48367d94ccb4411f15d7ef9c455c92125f3ad812f2363c4d2e949ce1b615429a"
      hash3 = "e8012a15b6f6b404a33f293205b602ece486d01337b8b3ec331cd99ccadb562e"
   strings:
      $s1 = "X-siLock-Comment" ascii fullword   
      $s2 = "]; string x = null;" ascii
      $s3 = ";  if (!String.Equals(pass, " ascii
   condition:
      filesize < 150KB and 2 of them
}
