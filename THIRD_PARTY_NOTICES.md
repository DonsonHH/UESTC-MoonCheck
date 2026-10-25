# Third-party acknowledgements and licenses

This distribution includes MoonUESTC integration and dashboard code from https://github.com/horoscope963852/MoonUESTC (MIT) and Donson's student portal, browser helper, private operator access and queue changes. The original copyright and permission notice remain in LICENSE. The MoonUESTC source base is upstream commit 69ebe71; the integrated deployment branch is maintained in DonsonHH/UESTC-MoonCheck. Current portal, scheduling and browser integration changes are maintained by Donson.

## Referenced projects

- Ryan-Orion/UESTC-MoonCheck, https://github.com/Ryan-Orion/UESTC-MoonCheck — MIT. Current reference for YYB OAuth, renewable grants and native mini-program login codes. The deployment also adapts CAS error diagnostics from commit `553b1dc`, included in the reviewed upstream head `6f14a3a`. The complete notice is preserved in third_party/mooncheck-LICENSE.txt.
- GoodNight, https://github.com/beichenO2/GoodNight — MIT. Referenced for current-day record checks, durable pre-submission claims, and reconciliation after uncertain submissions. The complete notice is preserved in third_party/GoodNight.LICENSE.
- Earlier UESTC-MoonCheck reference, https://github.com/richard297779/UESTC-MoonCheck — its supplied LICENSE contains the MIT permission and warranty text. The historical reference covered CAS login protocol, trusted-browser cookie, portal warmup and request schema.
- coordtransform, https://github.com/wandergis/coordtransform — MIT. WGS-84 forward-transform formulas are ported in moonuestc/coordinates.py. The complete notice is preserved in third_party/coordtransform.LICENSE.

## MoonCheck license formatting

The upstream LICENSE retrieved on 2026-10-18 (Git blob 480a7cb525870b36c6430e828fe544ab6747ce45) contains Git merge markers around two copyright notices:

- Copyright (c) 2026 MoonCheck contributors
- Copyright (c) 2026 richard297779

third_party/UESTC-MoonCheck.LICENSE retains BOTH notices and the entire MIT permission and warranty text; only the three merge-marker lines were removed. The byte-for-byte upstream file is retained as third_party/UESTC-MoonCheck.LICENSE.original. No attribution was selected over the other, no licensing permission was added, and this editorial normalization does not claim to resolve upstream authorship. The referenced upstream license blob is identified above and its original bytes remain in third_party/. The upstream projects themselves were not modified.

## Runtime dependencies

PyCryptodome, Flask, Waitress, argon2-cffi and their dependencies retain their own applicable license notices in the installed distributions. requirements.txt pins the versions; the Docker image installs their original wheels with license metadata intact.

## Coordinates and assets

The eight named campus presets use maintainer-provided AMap GCJ-02 coordinates. The original screenshot is not distributed. Coordinate conversion is an offline approximation rather than an official map calibration. Portal HTML, CSS, JavaScript and SVG are project code; no externally hosted fonts or JavaScript CDNs are used.

# Donson UI additions

The Donson frontend uses React, Radix Primitives, Sonner, Lucide and morphdom 2.7.8 (MIT), plus their runtime dependencies. Bundled license texts are retained under `third_party/ui/`. The frontend lockfile pins exact package versions.

# UESTC-MoonCheck authorization modules

The YYB OAuth and mini-program login-code protocol modules in
`moonuestc/yyb/` are adapted from Ryan-Orion/UESTC-MoonCheck, as forked at
DonsonHH/UESTC-MoonCheck commit `482c58d0f502bf0f7193b25bc5032e6a97c8ce28`.
They are used under the MIT license in `third_party/mooncheck-LICENSE.txt`.
The protocol implementation credits YYB-Go-Enhanced revision `8a9497397abc`.
Local changes use package-relative imports; account isolation, encrypted
persistence, school identity checks and portal integration are Donson additions.
