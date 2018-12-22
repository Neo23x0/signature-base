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

## High Quality YARA Rules Feed

If you liked my rules, please check our [commercial rule set and rule feed service](https://www.nextron-systems.com/2018/12/21/yara-rule-sets-and-rule-feed/), which contains better and 20 times the number of rules.

## License

![Creative Commons License](https://i.creativecommons.org/l/by-nc/4.0/88x31.png)

All signatures and IOC files in this repository, except the YARA rules created by 3rd parties, are licensed under the [Creative Commons Attribution-NonCommercial 4.0 International License](http://creativecommons.org/licenses/by-nc/4.0/).

The license of this repository changed in August 2018. All forks or copies of this repository that were created before August 26th of 2018 are licensed under GPL 3.0. you can find the [last GPL version](https://github.com/Neo23x0/signature-base/releases/tag/v1.0) in the release section.
