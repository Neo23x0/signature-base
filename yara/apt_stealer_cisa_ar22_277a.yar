
/* slightly modified by Florian Roth */

rule APT_MAL_CISA_10365227_03_ClientUploader_Dec21 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-12-23"
       modified = "2021-12-24"
       score = 80
       description = "Detects ClientUploader onedrv"
       reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
       hash1 = "84164e1e8074c2565d3cd178babd93694ce54811641a77ffdc8d1084dd468afb"
       id = "4eeadb28-9312-5602-932a-36acb48772f4"
   strings:
       $s1 = "Decoder2"
       $s2 = "ClientUploader"
       $s3 = "AppDomain"
       $s4 = { 5F 49 73 52 65 70 47 ?? 44 65 63 6F 64 65 72 73 }
       $s5 = "LzmaDecoder"
       $s6 = "$ee1b3f3b-b13c-432e-a461-e52d273896a7"
   condition:
       uint16(0) == 0x5a4d and all of them
}

rule APT_MAL_CISA_10365227_01_APPSTORAGE_Dec21 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-12-23"
       modified = "2021-12-24"
       family = "APPSTORAGE"
       score = 80
       description = "Detects AppStorage ntstatus msexch samples"
       reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
       hash1 = "157a0ffd18e05bfd90a4ec108e5458cbde01015e3407b3964732c9d4ceb71656"
       hash2 = "30191b3badf3cdbc65d0ffeb68e0f26cef10a41037351b0f562ab52fce7432cc"
       id = "a44c5609-980f-5961-921c-6b1824cdd49c"
   strings:
       $s1 = "026B924DD52F8BE4A3FEE8575DC"
       $s2 = "GetHDDId"
       $s3 = "AppStorage"
       $s4 = "AppDomain"
       $s5 = "$1e3e5580-d264-4c30-89c9-8933c948582c"
       $s6 = "hrjio2mfsdlf235d" wide
   condition:
       uint16(0) == 0x5a4d and all of them
}

rule APT_MAL_CISA_10365227_02_ClientUploader_Dec21 {
   meta:
       author = "CISA Code & Media Analysis"
       date = "2021-12-23"
       modified = "2021-12-24"
       score = 80
       description = "Detects ClientUploader_mqsvn"
       reference = "https://www.cisa.gov/uscert/ncas/analysis-reports/ar22-277a"
       hash1 = "3585c3136686d7d48e53c21be61bb2908d131cf81b826acf578b67bb9d8e9350"
       id = "84351df9-e225-5c3f-9385-523246681a97"
   strings:
       $s1 = "UploadSmallFileWithStopWatch"
       $s2 = "UploadPartWithStopwatch"
       $s3 = "AppVClient"
       $s4 = "ClientUploader"
       $s5 = { 46 69 6C 65 43 6F 6E 74 61 69 6E 65 72 2E 46 69 6C 65 41 72 63 68 69 76 65 }
       $s6 = { 4F 6E 65 44 72 69 76 65 43 6C 69 65 6E 74 2E 4F 6E 65 44 72 69 76 65 }
   condition:
       uint16(0) == 0x5a4d and all of them
}