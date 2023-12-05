rule CrowdStrike_SUNSPOT_01 : artifact stellarparticle sunspot {

    meta:
        author = "(c) 2021 CrowdStrike Inc."
        description = "Detects RC4 and AES key encryption material in SUNSPOT"
        reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"
        version = "202101081448"
        date = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"

        id = "2a2a5cfc-d059-5942-bd70-c3169e9ceb45"
    strings:

        $key = {fc f3 2a 83 e5 f6 d0 24 a6 bf ce 88 30 c2 48 e7}
        $iv  = {81 8c 85 49 b9 00 06 78 0b e9 63 60 26 64 b2 da}

    condition:
        all of them and filesize < 32MB

}

rule CrowdStrike_SUNSPOT_02 : artifact stellarparticle sunspot
{

    meta:
        copyright = "(c) 2021 CrowdStrike Inc."
        description = "Detects mutex names in SUNSPOT"
        version = "202101081448"
        date = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"
        reference = "https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/"

        id = "9ecb89e6-475b-5961-8a67-136a0274e1c7"
    strings:
        $mutex_01 = "{12d61a41-4b74-7610-a4d8-3028d2f56395}" wide ascii
        $mutex_02 = "{56331e4d-76a3-0390-a7ee-567adf5836b7}" wide ascii

    condition:
        any of them and filesize < 10MB

}

rule CrowdStrike_SUNSPOT_03 : artifact logging stellarparticle sunspot 

{

    meta:
        copyright = "(c) 2021 CrowdStrike Inc."
        description = "Detects log format lines in SUNSPOT"
        version = "202101081443"
        last_modified = "2021-01-08"
        actor = "StellarParticle"
        malware_family = "SUNSPOT"

        id = "5535163e-a85a-587d-bb6e-083783f915c9"
    strings:
        $s01 = "[ERROR] ***Step1('%ls','%ls') fails with error %#x***\x0A" ascii
        $s02 = "[ERROR] Step2 fails\x0A" ascii
        $s03 = "[ERROR] Step3 fails\x0A" ascii
        $s04 = "[ERROR] Step4('%ls') fails\x0A" ascii
        $s05 = "[ERROR] Step5('%ls') fails\x0A" ascii
        $s06 = "[ERROR] Step6('%ls') fails\x0A" ascii
        $s07 = "[ERROR] Step7 fails\x0A" ascii
        $s08 = "[ERROR] Step8 fails\x0A" ascii
        $s09 = "[ERROR] Step9('%ls') fails\x0A" ascii
        $s10 = "[ERROR] Step10('%ls','%ls') fails with error %#x\x0A" ascii
        $s11 = "[ERROR] Step11('%ls') fails\x0A" ascii
        $s12 = "[ERROR] Step12('%ls','%ls') fails with error %#x\x0A" ascii
        $s13 = "[ERROR] Step30 fails\x0A" ascii
        $s14 = "[ERROR] Step14 fails with error %#x\x0A" ascii
        $s15 = "[ERROR] Step15 fails\x0A" ascii
        $s16 = "[ERROR] Step16 fails\x0A" ascii
        $s17 = "[%d] Step17 fails with error %#x\x0A" ascii
        $s18 = "[%d] Step18 fails with error %#x\x0A" ascii
        $s19 = "[ERROR] Step19 fails with error %#x\x0A" ascii
        $s20 = "[ERROR] Step20 fails\x0A" ascii
        $s21 = "[ERROR] Step21(%d,%s,%d) fails\x0A" ascii
        $s22 = "[ERROR] Step22 fails with error %#x\x0A" ascii
        $s23 = "[ERROR] Step23 fails with error %#x\x0A" ascii
        $s24 = "[%d] Solution directory: %ls\x0A" ascii
        $s25 = "[%d] %04d-%02d-%02d %02d:%02d:%02d:%03d %ls\x0A" ascii
        $s26 = "[%d] + '%s' " ascii

    condition:
        2 of them and filesize < 10MB
}