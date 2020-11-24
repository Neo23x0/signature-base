/*
   MIT License

   Copyright (c) 2020 nao_sec

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

rule RoyalRoad_code_pattern1
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
   strings:
       $S1= "48905d006c9c5b0000000000030101030a0a01085a5ab844eb7112ba7856341231"
       $RTF= "{\\rt"

   condition:
       $RTF at 0 and $S1
}

rule RoyalRoad_code_pattern2
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
    strings:
        $S1= "653037396132353234666136336135356662636665" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}

rule RoyalRoad_code_pattern3
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
strings:
    $S1="4746424151515151505050500000000000584242eb0642424235353336204460606060606060606061616161616161616161616161616161"
    $RTF= "{\\rt"

condition:
    $RTF at 0 and $S1

}

rule RoyalRoad_code_pattern4ab
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
    strings:
        $S1= "4746424151515151505050500000000000584242EB064242423535333620446060606060606060606161616161616}1616161616161616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}

rule RoyalRoad_code_pattern4ce
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
    strings:
        $S1= "584242eb064242423535333620446060606060606060606161616161616161616161616}1616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}



rule RoyalRoad_code_pattern4d
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
    strings:
        $S1= "584242eb06424242353533362044606060606060606060616161616161616161616}16161616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}


/* Hunting */

rule RoyalRoad_RTF
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 80
    strings:
        $S1= "objw2180\\objh300" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}

rule RoyalRoad_RTF_v7
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 60
    strings:
        $v7_1= "{\\object\\objocx{\\objdata" ascii
        $v7_2= "ods0000"  ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and all of ($v7*)
}

rule RoyalRoad_encode_in_RTF
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "neo_sec"
      score = 60
    strings:
        $enc_hex_1 = "B0747746"
        $enc_hex_2 = "B2A66DFF"
        $enc_hex_3 = "F2A32072"
        $enc_hex_4 = "B2A46EFF"
        $enc_hex_1l = "b0747746"
        $enc_hex_2l = "b2a66Dff"
        $enc_hex_3l = "f2a32072"
        $enc_hex_4l = "b2a46eff"
        $RTF= "{\\rt"
    condition:
        $RTF at 0 and 1 of ($enc_hex*)
}
