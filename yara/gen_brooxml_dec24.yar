
rule Brooxml_Hunting {
    meta:
        description = "Detects Microsoft OOXML files with prepended data/manipulated header"
        author = "Proofpoint"
        category = "hunting"
        date = "2024-11-27"
        modified = "2025-06-02"
        score = 70
        reference = "https://x.com/threatinsight/status/1861817946508763480"
        id = "1ffea1c7-9f97-5bb1-93d7-ce914765416f"
    strings:
        $pk_ooxml_magic = {50 4b 03 04 [22] 13 00 [2] 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c}

        $pk_0102 = {50 4b 01 02}
        $pk_0304 = {50 4b 03 04}
        $pk_0506 = {50 4b 05 06}
        $pk_0708 = {50 4b 07 08}

        $word = "word/"

        // Negations for FPs / unwanted file types
        $ole = {d0 cf 11 e0}
        $tef = {78 9f 3e 22}
    condition:
        $pk_ooxml_magic in (4..16384) and
        $pk_0506 in (16384..filesize) and
        #pk_0506 == 1 and
        #pk_0102 > 2 and
        #pk_0304 > 2 and
        $word and
        not ($pk_0102 at 0) and
        not ($pk_0304 at 0) and
        not ($pk_0506 at 0) and
        not ($pk_0708 at 0) and
        not ($ole at 0) and
        not (uint16(0) == 0x5a4d) and
        not ($tef at 0)
}

rule Brooxml_Phishing {
    meta:
        description = "Detects PDF and OOXML files leading to AiTM phishing"
        author = "Proofpoint"
        category = "phishing"
        date = "2024-11-27"
        score = 65
        reference = "https://x.com/threatinsight/status/1861817946508763480"
        id = "ccd8ab30-90a4-5d4b-8a77-dbc4669bdb95"
    strings:
        $hex1 = { 21 20 03 20 c3 be c3 bf 09 20 [0-1] 06 20 20 20 20 20 20 20 20 20 20 20 01 20 20 20 06 20 20 20 20 20 20 20 20 10 20 20 05 20 20 20 01 20 20 20 c3 be c3 bf c3 bf c3 bf }
    condition:
        all of ($hex*) and ((uint16be(0) == 0x504b) or (uint32be(0) == 0x25504446))
}
