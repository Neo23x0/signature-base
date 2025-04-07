rule Octowave_Installer_03_2025
{
    meta:
        description = "Detects resources embedded within Octowave Loader MSI installers"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-28"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "05b025b8475c0acbc9a5d2cd13c15088a2fb452aa514d0636f145e1c4c93e6ee"
        hash2 = "500462c4fb6e4d0545f04d63ef981d9611b578948e5cfd61d840ff8e2f206587"
        hash3 = "5ee9e74605b0c26b39b111a89139d95423e54f7a54decf60c7552f45b8b60407"
        hash4 = "76efc8c64654d8f2318cc513c0aaf0da612423b1715e867b4622712ba0b3926f"
        hash5 = "c3e2af892b813f3dcba4d0970489652d6f195b7985dc98f08eaddca7727786f0"
        hash6 = "d7816ba6ddda0c4e833d9bba85864de6b1bd289246fcedae84b8a6581db3f5b6"
        hash7 = "e93969a57ef2a7aee13a159cbf2015e2c8219d9153078e257b743d5cd90f05cb"
        hash8 = "45984ae78d18332ecb33fe3371e5eb556c0db86f1d3ba8a835b72cd61a7eeecf"
        id = "56685a0a-523d-4060-a008-aa28542cb85c"
    strings:
        $string1 = "LaunchConditionsValidateProductIDProcessComponentsUnpublishFeaturesRemoveFilesRegisterUserRegisterProductInstalled OR PhysicalMemory >= 2048" ascii
        $string2 = ".cab" ascii
        $string3 = ".wav" ascii
        $string4 = ".dll" ascii
        
        $supporting1 = ".raw" ascii
        $supporting2 = ".db" ascii
        $supporting3 = ".pak" ascii
        $supporting4 = ".bin" ascii
        $supporting5 = ".bak" ascii
        $supporting6 = ".dat" ascii
    condition:
        (uint32(0) == 0xe011cfd0)
        and filesize < 200000KB
        and all of ($string*)
        and 1 of ($supporting*)
}