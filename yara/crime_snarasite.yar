import "pe"

rule BKDR_Snarasite_Oct17 {
   meta:
      description = "Auto-generated rule - file 36ba92cba23971ca9d16a0b4f45c853fd5b3108076464d5f2027b0f56054fd62"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-10-07"
      hash1 = "36ba92cba23971ca9d16a0b4f45c853fd5b3108076464d5f2027b0f56054fd62"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
         pe.imphash() == "322bef04e1e1ac48875036e38fb5c23c" or
         pe.imphash() == "15088754757513c92fa36ba5590e907b"
      )
}
