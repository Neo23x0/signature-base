rule gen_excel_auto_open_evasion
{
    meta:
        description = "Detects an obfuscated Auto_Open cell names in Excel files"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
        author = "@JohnLaTwC"
        date = "2020-09-24"
        reference="https://malware.pizza/2020/05/12/evading-av-with-excel-macros-and-biff8-xls/"
        hash="e23f9f55e10f3f31a2e76a12b174b6741a2fa1f51cf23dbd69cf169d92c56ed5"
        hash1="bb3c9739de8ffe2e0f375847d41a010463ec19f1d3f578ac053651a51ed69bbc"
        hash2="56ff65b7f6bf5936883f52b50ca66e768b2088158cc77af681ffab7122be7753"
        hash3="97243214ac3cad74d60b0648e39d6a9600860edba51c670b5226e058ba658957"
        hash4="9ebf085c05ae94c1b6c4e011001a6c11de3ca754a56ed380314ef501b777e593"
        hash5="b5a8bbf3c7d49bd208d8302f6867b5f6d3d7c09830b575967801893498cc92d9"
        score = 70
        id = "e33b8d1d-4978-5747-8b5b-730e6c57dbf0"
    strings:
        $auto_open = { 00 00 00 00 01 [0-2] (61 | 41) [0-5](75 | 55) [0-5](74 | 54) [0-5](6f | 4f) [0-5](5f | 5f) [0-5](6f | 4f) [0-5](70 | 50) [0-5](65 | 45) [0-5](6e | 4e)}

        $plain_auto_open = "auto_open" nocase wide ascii

    condition:
        filesize < 1MB
        and uint32be(0) == 0xD0CF11E0
        and $auto_open and #plain_auto_open == 0
}
