rule gen_suspicious_InPage_dropper
{

    meta:
        hash1 = "013417bd5465d6362cd43c70015c7a74a1b8979785b842b7cfa543cb85985852"
        hash2 = "1d1e7a6175e6c514aaeca8a43dabefa017ddc5b166ccb636789b6a767181a022"
        hash3 = "bd293bdf3be0a44a92bdb21e5fa75c124ad1afed3c869697bf90c9732af0e994"
        hash4 = "d8edf3e69f006f85b9ee4e23704cd5e95e895eb286f9b749021d090448493b6f"
        url1 = "https://cloudblogs.microsoft.com/microsoftsecure/2018/11/08/attack-uses-malicious-inpage-document-and-outdated-vlc-media-player-to-give-attackers-backdoor-access-to-targets/"
        url2 = "https://twitter.com/Ahmedfshosha/status/1138138981521154049"

        id = "9144711a-e6ee-5c97-a5f4-3f6df1d630dc"
    strings:
        $s1 = "InPage Arabic Document"
        $c1 = {31 06 83 c6 04 e2 }
        $c2 = {90 90 90 90 90 90 90 e8 fb }

    condition:
        filesize < 3MB
        and uint32be(0) == 0xD0CF11E0
        and $s1 
        and 1 of ($c*)
}
