import "math"

rule php_obfuscated   {

meta:
        author = "Jeff Beley"
        description = "Detects base64 obfuscated php webshells"
        date = "2019-11-02"

strings:
        $a1 = "<?"
        $a4 = /[A-Za-z0-9+\/=]{50,}/
        $bad = "abcdefghijklmnopqrstuvwxyz"
        $p1 = "create_function" ascii wide nocase
        $p2 = "str_replace" ascii wide nocase
        $p3 = "base64_decode" ascii wide nocase
        $p4 = "gzinflate" ascii wide nocase
        $p5 = "eval" ascii wide nocase
        $p6 = "strrev" ascii wide nocase
        $p7 = "str_rot13" ascii wide nocase
        $p8 = "rawurldecode" ascii wide nocase
        $p9 = "gzuncompress" ascii wide nocase

condition:
        $a1
        and
		math.entropy(0, filesize) >=  4
        and not $bad
        and 1 of ($p*,$a4)
}
