rule Octowave_Loader_Supporting_File_03_2025
{
    meta:
        description = "Detects supporting file used by Octowave Loader containing hardcoded values"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-19"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "C4CBAA7E4521FA0ED9CC634C5E2BACBF41F46842CA4526B7904D98843A7E9DB9"
        hash2 = "F5CFB2E634539D5DC7FFE202FFDC422EF7457100401BA1FBC21DD05558719865"
        hash3 = "56F1967F7177C166386D864807CDF03D5BBD3F118A285CE67EA226D02E5CF58C"
        hash4 = "11EE5AD8A81AE85E5B7DDF93ADF6EDD20DE8460C755BF0426DFCBC7F658D7E85"
        hash5 = "D218B65493E4D9D85CBC2F7B608F4F7E501708014BC04AF27D33D995AA54A703"
        hash6 = "0C112F9DFE27211B357C74F358D9C144EA10CC0D92D6420B8742B72A65562C5A"
    strings:
        $unique_key = {1D 1C 1F 1E 01 01 03 02 05 04 07 06 09 D4 0E 0A 0D 0C 0F 0E 31 30 31 32 35 34 36 36 39 38 DC 3F 3D 3C 3E} // 1012546698 unknown unique identifier and surrounding bytes
        $unique_string = "MLONqpsrutwvyx"
        $unique_string2 = "A@CBEDGFIHKJMLONqpsrutwvyx"
    condition:
        (uint16(0) != 0x5a4d)
        and filesize < 10000KB
        and all of them
}