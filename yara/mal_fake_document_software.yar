rule MAL_Fake_Document_Software_Indicators_Nov23 {
   meta:
      description = "Detects indicators of fake document/image utility software that acts as a downloader for additional malware"
      author = "Jonathan Peters"
      date = "2023-11-13"
      reference = "https://nochlab.blogspot.com/2023/09/net-in-javascript-fake-pdf-converter.html"
      hash1 = "ac5356ae011effb9d401bf428c92a48cf82c9b61f4c24a29a9718e3379f90f1d"
      hash2 = "d1c29c2243c511ca3264ad568a6be62f374e104b903eca93debce6691e1c5007"
      score = 80
      id = "231474cd-1ec9-5738-bf48-ef707689056d"
   strings:
      $ = "tweakscode.com" wide
      $ = "www.createmygif.com" wide
      $ = "www.videownload.com" wide
      $ = "www.pdfconverterz.com" wide
      $ = "www.pdfconvertercompare.com" wide
   condition:
      uint16(0) == 0x5a4d
      and 1 of them
}
