
rule APT_MAL_MalDoc_CloudAtlas_Oct20_1 {
   meta:
      description = "Detects unknown maldoc dropper noticed in October 2020"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1316050637092651009"
      date = "2020-10-13"
      hash1 = "7ba76b2311736dbcd4f2817c40dae78f223366f2404571cd16d6676c7a640d70"
   strings:
      $x1 = "https://msofficeupdate.org" wide
   condition:
      uint16(0) == 0xcfd0 and
      filesize < 300KB and
      1 of ($x*)
}

rule APT_MAL_URL_CloudAtlas_Oct20_2 {
   meta:
      description = "Detects unknown maldoc dropper noticed in October 2020 - file morgue6visible5bunny6culvert7ambo5nun1illuminate4.url"
      author = "Florian Roth"
      reference = "https://twitter.com/jfslowik/status/1316050637092651009"
      date = "2020-10-13"
      hash1 = "a6a58b614a9f5ffa1d90b5d42e15521f52e2295f02c1c0e5cd9cbfe933303bee"
   strings:
      /* [InternetShortcut]
         URL=https://msofficeupdate.org/ */
      $hc1 = { 5B 49 6E 74 65 72 6E 65 74 53 68 6F 72 74 63 75
               74 5D 0D 0A 55 52 4C 3D 68 74 74 70 73 3A 2F 2F
               6D 73 6F 66 66 69 63 65 75 70 64 61 74 65 2E 6F
               72 67 }
   condition:
      uint16(0) == 0x495b and
      filesize < 200 and
      $hc1 at 0
}
