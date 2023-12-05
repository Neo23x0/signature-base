rule MAL_ZIP_SocGholish_Mar21_1 : zip js socgholish {
    meta:
        description = "Triggers on small zip files with typical SocGholish JS files in it"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        hash = "4f6566c145be5046b6be6a43c64d0acae38cada5eb49b2f73135b3ac3d6ba770"
        hash = "54f756fbf8c20c76af7c9f538ff861690800c622d1c9db26eb3afedc50835b09"
        hash = "dfdbec1846b74238ba3cfb8c7580c64a0fa8b14b6ed2b0e0e951cc6a9202dd8d"
        id = "da35eefd-b34d-59cd-8afc-da9c78ace96e"
    strings:
        $a1 = /\.[a-z0-9]{6}\.js/ ascii
        $a2 = "Chrome" ascii
        $a3 = "Opera" ascii

        $b1 = "Firefox.js" ascii
        $b2 = "Edge.js" ascii
    condition:
        uint16(0) == 0x4b50 and filesize < 1600 and (
            2 of ($a*) or
            any of ($b*)
        )
}

/* modified rule: too many matches with 'try' */
rule EXT_MAL_JS_SocGholish_Mar21_1 : js socgholish {
    meta:
        description = "Triggers on SocGholish JS files"
        author = "Nils Kuhnert"
        date = "2021-03-29"
        modified = "2023-01-02"
        hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
        hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
        hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
        id = "3ed7d2da-569b-5851-a821-4a3cda3e13ce"
    strings:
        /* $try = "try" ascii */

        $s1 = "new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s2 = "['DeleteFile']" ascii
        $s3 = "['WScript']['ScriptFullName']" ascii
        $s4 = "['WScript']['Sleep'](1000)" ascii
        $s5 = "new ActiveXObject('MSXML2.XMLHTTP')" ascii
        $s6 = "this['eval']" ascii
        $s7 = "String['fromCharCode']"
        $s8 = "2), 16)," ascii
        $s9 = "= 103," ascii
        $s10 = "'00000000'" ascii
    condition:
        //$try in (0 .. 10) and 
        filesize > 3KB and filesize < 5KB and 8 of ($s*)
}

rule SocGholish_JS_22_02_2022 {
    meta:
        description = "Detects SocGholish fake update Javascript files 22.02.2022"
        author = "Wojciech Cieślak"
        date = "2022-02-22"
        hash = "3e14d04da9cc38f371961f6115f37c30"
        hash = "dffa20158dcc110366f939bd137515c3"
        hash = "afee3af324951b1840c789540d5c8bff"
        hash = "c04a1625efec27fb6bbef9c66ca8372b"
        hash = "d08a2350df5abbd8fd530cff8339373e"
    
        id = "68d2dbb7-0079-527a-92c7-450c3dd953b3"
    strings:
        $s1 = "encodeURIComponent(''+" ascii
        $s2 = "['open']('POST'," ascii 
        $s3 = "new ActiveXObject('MSXML2.XMLHTTP');" ascii
    
    condition:
        filesize < 5KB and all of them
}

