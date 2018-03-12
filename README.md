[![Build Status](https://travis-ci.org/Neo23x0/signature-base.svg?branch=master)](https://travis-ci.org/Neo23x0/signature-base)

# Signature-Base
signature-base is a submodule for my scanner tools LOKI and SPARK

## Directory Structure

- iocs - Simple IOC files (CSV)
- yara - YARA rules
- threatintel - Threat Intel API Receiver (MISP, OTX)
- misc - Other input files (not IOCs or signatures)

## External Variables in YARA Rules

Using the YARA rules in a tool other than [LOKI](https://github.com/Neo23x0/Loki) will cause errors stating an `undefined identifier`. The rules that make use of external variables have been moved to the following 4 rule set files:

- ./yara/generic_anomalies.yar
- ./yara/general_cloaking.yar
- ./yara/thor_inverse_matches.yar
- ./yara/yara_mixed_ext_vars.yar

## License
The signature-base repository is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This signature-base is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICLAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with the signature-base repository.  If not, see <http://www.gnu.org/licenses/>.
