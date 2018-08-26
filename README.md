[![Build Status](https://travis-ci.org/Neo23x0/signature-base.svg?branch=master)](https://travis-ci.org/Neo23x0/signature-base)

# Signature-Base

signature-base is the signature database for my scanners LOKI and SPARK Core

## Directory Structure

- iocs - Simple IOC files (CSV)
- yara - YARA rules
- threatintel - Threat Intel API Receiver (MISP, OTX)
- misc - Other input files (not IOCs or signatures)

## External Variables in YARA Rules

Using the YARA rules in a tool other than [LOKI](https://github.com/Neo23x0/Loki), [SPARK](https://www.nextron-systems.com/spark/) or [SPARK Core](https://www.nextron-systems.com/spark-core/) will cause errors stating an `undefined identifier`. The rules that make use of external variables have been moved to the following 4 rule set files:

- ./yara/generic_anomalies.yar
- ./yara/general_cloaking.yar
- ./yara/thor_inverse_matches.yar
- ./yara/yara_mixed_ext_vars.yar

## License

![Creative Commons License](https://i.creativecommons.org/l/by-nc/4.0/88x31.png)

All signatures and IOC files in this repository, except the ones created by 3rd parties, are licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/).
