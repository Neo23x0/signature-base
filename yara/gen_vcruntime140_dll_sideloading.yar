import "pe" 

rule SUSP_VCRuntime_Sideloading_Indicators_Aug23 {
   meta:
      description = "Detects indicators of .NET based malware sideloading as VCRUNTIME140 with .NET DLL imports"
      author = "Jonathan Peters"
      date = "2023-08-30"
      hash = "b4bc73dfe9a781e2fee4978127cb9257bc2ffd67fc2df00375acf329d191ffd6"
      score = 75
      id = "00400122-1343-5051-af31-880a3ef1745d"
   condition:
      (filename == "VCRUNTIME140.dll" or filename == "vcruntime140.dll")
      and pe.imports("mscoree.dll", "_CorDllMain")
}

// rule SUSP_VCRuntime_Sideloading_Indicators_1_Aug23 {
//    meta:
//       description = "Detects indicators of .NET based malware sideloading as an unsigned VCRUNTIME140"
//       author = "Jonathan Peters"
//       date = "2023-08-30"
//       hash = "b4bc73dfe9a781e2fee4978127cb9257bc2ffd67fc2df00375acf329d191ffd6"
//       score = 75
//    strings:
//       $fp1 = "Wine builtin DLL" ascii
//    condition:
//       (filename == "VCRUNTIME140.dll" or filename == "vcruntime140.dll")
//       and not pe.number_of_signatures == 0
//       and not pe.signatures[0].issuer contains "Microsoft Corporation"
//       and not $fp1
// }
