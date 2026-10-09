Third-Party Notices
Unicode Confusables Data

This project includes the file confusables.txt, version 17.0.0, produced by the Unicode Consortium for Unicode Technical Standard #39, Unicode Security Mechanisms.

Copyright © 1991–2026 Unicode, Inc.

Unicode and the Unicode Logo are registered trademarks of Unicode, Inc. in the United States and other countries.

The Unicode data is distributed under the Unicode License v3. The complete license is available at:

https://www.unicode.org/license.txt

Sources
Unicode confusables data: https://www.unicode.org/Public/17.0.0/security/confusables.txt
Unicode Technical Standard #39: https://www.unicode.org/reports/tr39/
Unicode terms of use: https://www.unicode.org/terms_of_use.html

The Unicode dataset retains its original copyright and licensing terms. The MIT License in this repository applies to the project’s original Python source code and does not replace the license applicable to the Unicode data.

Domain-boundary parsing

This application depends on tldextract 5.3.0 (BSD-3-Clause), which includes a
bundled Public Suffix List snapshot. Runtime suffix fetching and disk caching
are disabled. Both ICANN and private suffix rules are used. Reserved .test
is explicitly supported for safe development examples. This is name parsing,
not DNS, registration, ownership, or network verification.

https://github.com/john-kurkowski/tldextract
https://publicsuffix.org/
