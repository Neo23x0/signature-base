/* Limited support for hash function */

/*
import"pe"
import"hash"

rule FLAME2_Orchestrator {
   meta:
      desc = "Encrypted resources in Flame2.0 Orchestrators"
      author = "turla @ Uppercase"
      hash1 = "15a9b1d233c02d1fdf80071797ff9077f6ac374958f7d0f2b6e84b8d487c9cd1" 
      hash2 = "426aa55d2afb9eb08b601d373671594f39a1d9d9a73639c4a64f17d674ca9a82" 
      hash3 = "af8ccd0294530c659580f522fcc8492d92c2296dc068f9a42474d52b2b2f16e4"
      reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
   condition: 
      for any i in (0..pe.number_of_resources-1):
      ((hash.md5(pe.resources[i].offset,pe.resources[i].length) == "53b19d9863d8ff8cde8e4358d1b57c04") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "4849cc439e524ef6a9964a3666dddb13") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "62bfe21a8eb76fd07e22326c0073fef5") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "dfed2c71749b04dad46d0ce52834492c") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "9119aa701b39242a98be118d9c237ecc") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "b69d168e29fba6c88ad4e670949815aa") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "4849cc439e524ef6a9964a3666dddb13") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "1933a1e254b1657a6a2eb8ad1fbe6fa3") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "dfed2c71749b04dad46d0ce52834492c") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "9119aa701b39242a98be118d9c237ecc") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "b69d168e29fba6c88ad4e670949815aa") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "17c794f7056349cb82889b5e5b030d15") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "e15187f79b6916cb6763d29d215623c1") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "923963bb24f2e2ceac9f9759071dba88") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "9a2766aba7f2a56ef1ab24cf171ee0ed") or
      (hash.md5(pe.resources[i].offset,pe.resources[i].length) == "ebe15bfb5a3944ea4952ddf0f73aa6e8"))
}
*/