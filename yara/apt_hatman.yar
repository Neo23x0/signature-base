/*
 * DESCRIPTION: Yara rules to match the known binary components of the HatMan
 *              malware targeting Triconex safety controllers. Any matching
 *              components should hit using the "hatman" rule in addition to a
 *              more specific "hatman_*" rule.
 * AUTHOR:      DHS/NCCIC/ICS-CERT
 */

/* Globally only look at small files. */

/* Disabled global rule to avoid applying this rule to the full concatenated
   rule set
private global rule hatman_filesize : hatman {
    condition:
        filesize < 100KB
}
*/

/* Private rules that are used at the end in the public rules. */

private rule hatman_setstatus : hatman {
   uuid = "a0619dad-7cee-585a-9246-b3d4554e512f"
    strings:
        $preset     = { 80 00 40 3c  00 00 62 80  40 00 80 3c  40 20 03 7c
                        ?? ?? 82 40  04 00 62 80  60 00 80 3c  40 20 03 7c
                        ?? ?? 82 40  ?? ?? 42 38                           }
    condition:
        $preset
}
private rule hatman_memcpy : hatman {
   uuid = "2eb11f72-b37f-563f-8ce9-c4d4388598d3"
    strings:
        $memcpy_be  = { 7c a9 03 a6  38 84 ff ff  38 63 ff ff  8c a4 00 01
                        9c a3 00 01  42 00 ff f8  4e 80 00 20              }
        $memcpy_le  = { a6 03 a9 7c  ff ff 84 38  ff ff 63 38  01 00 a4 8c
                        01 00 a3 9c  f8 ff 00 42  20 00 80 4e              }
    condition:
        $memcpy_be or $memcpy_le
}
private rule hatman_dividers : hatman {
   uuid = "1612a184-e06c-5c1b-987d-04e330e17ed0"
    strings:
        $div1       = { 9a 78 56 00 }
        $div2       = { 34 12 00 00 }
    condition:
        $div1 and $div2
}
private rule hatman_nullsub : hatman {
   uuid = "1b0e708d-6e4c-5688-9fc6-c31a4fb3c4a8"
    strings:
        $nullsub     = { ff ff 60 38  02 00 00 44  20 00 80 4e }
    condition:
        $nullsub
}
private rule hatman_origaddr : hatman {
   uuid = "5eb29f1f-f49f-54e9-8a9e-ba10fc9c826e"
    strings:
        $oaddr_be   = { 3c 60 00 03  60 63 96 f4  4e 80 00 20 }
        $oaddr_le   = { 03 00 60 3c  f4 96 63 60  20 00 80 4e }
    condition:
        $oaddr_be or $oaddr_le
}
private rule hatman_origcode : hatman {
   uuid = "582b4cb6-54b5-5128-8c42-6759ec0f3976"
    strings:
        $ocode_be   = { 3c 00 00 03  60 00 a0 b0  7c 09 03 a6  4e 80 04 20 }
        $ocode_le   = { 03 00 00 3c  b0 a0 00 60  a6 03 09 7c  20 04 80 4e }
    condition:
        $ocode_be or $ocode_le
}
private rule hatman_mftmsr : hatman {
   uuid = "cbbd6008-7722-5d92-bb82-73c8b2b6bea9"
    strings:
        $mfmsr_be   = { 7c 63 00 a6 }
        $mfmsr_le   = { a6 00 63 7c }
        $mtmsr_be   = { 7c 63 01 24 }
        $mtmsr_le   = { 24 01 63 7c }
    condition:
        ($mfmsr_be and $mtmsr_be) or ($mfmsr_le and $mtmsr_le)
}
private rule hatman_loadoff : hatman {
   uuid = "1ad2f77b-4360-512d-ac06-9933ac2cdc67"
    strings:
        $loadoff_be = { 80 60 00 04  48 00 ?? ??  70 60 ff ff  28 00 00 00
                        40 82 ?? ??  28 03 00 00  41 82 ?? ??              }
        $loadoff_le = { 04 00 60 80  ?? ?? 00 48  ff ff 60 70  00 00 00 28
                        ?? ?? 82 40  00 00 03 28  ?? ?? 82 41              }
    condition:
        $loadoff_be or $loadoff_le
}

/* Actual public rules to match using the private rules. */

rule hatman_compiled_python : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        author = "DHS/NCCIC/ICS-CERT"
        uuid = "fd156669-72b4-59a5-8f36-aac21d7b3105"
    condition:
        hatman_nullsub and hatman_setstatus and hatman_dividers
}
rule hatman_injector : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        modified = "2023-01-09"
        author = "DHS/NCCIC/ICS-CERT"
        uuid = "b939b83d-cc4a-5998-89a7-8abf8d0b8592"
    condition:
        ( hatman_memcpy and hatman_origaddr and hatman_loadoff )
}
rule hatman_payload : hatman {
    meta:
        description = "Detects Hatman malware"
        reference = "https://ics-cert.us-cert.gov/MAR-17-352-01-HatMan%E2%80%94Safety-System-Targeted-Malware"
        date = "2017/12/19"
        author = "DHS/NCCIC/ICS-CERT"
        uuid = "9ef57fca-a536-5937-8510-b410f735a73e"
    condition:
        ( hatman_memcpy and hatman_origcode and hatman_mftmsr ) and not ( hatman_origaddr and hatman_loadoff )
}
