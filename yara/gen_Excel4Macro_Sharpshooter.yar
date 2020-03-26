rule gen_Excel4Macro_Sharpshooter
{
    meta:
        description = "Detects suspicious Excel4 macros by identifying concatenation used to build the shellcode payload "
        author = "John Lambert @JohnLaTwC"
        date = "2020-03-26"
        hash="ccef64586d25ffcb2b28affc1f64319b936175c4911e7841a0e28ee6d6d4a02d"
        reference1="https://github.com/mdsecactivebreach/SharpShooter/blob/master/modules/excel4.py"
        reference2="https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/"
        reference3 = "https://gist.github.com/JohnLaTwC/efab89650d6fcbb37a4221e4c282614c"
        reference4 = "https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/00b5dd7d-51ca-4938-b7b7-483fe0e5933b"
    strings:
        $header_docf = { D0 CF 11 E0 }
        $s1 = "Excel 4.0 Macros" 
        $s2 = "CreateThread"

        // ##   Detect concatenations CHAR(123)&CHAR(101)&...
        // ##   \x1e\xc9\x00Ao\x00\x08
        // ##   
        // ##   to 
        // ##   \x1e      : ptgInt
        // ##   \xc9\x00  : WORD 00c9 -->  201
        // ##   A         : ptgFuncV
        // ##   o \x00    : CHAR function (0x006f)
        // ##   \x08      : ptgConcat
        $concat = { 00 41 6f 00 08 1e ?? 00 41 6f 00 08 1e ?? 00 41 6f 00 08}
    condition:
        filesize < 400KB
        and $header_docf at 0 
        and #concat > 10
        and all of them
}
