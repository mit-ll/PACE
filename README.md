<!--
Copyright 2016 MIT Lincoln Laboratory
    
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

[Proactively-secure Accumulo with Cryptographic Enforcement (PACE)][pace]
--

The [PACE][pace] library adds cryptographic protections to
[Apache Accumulo][accumulo], with the goal of protecting data from a potentially
 malicious Accumulo server administrator. These include encrypting data
 ([encryption]) and signing data ([signature]) stored in Accumulo.

Installation
------------

To use PACE, include the core library as a maven dependency:

```xml
<dependency>
  <groupId>edu.mit.ll.pace</groupId>
  <artifactId>pace-core</artifactId>
  <version>1.0.0</version>
</dependency>
```

Documentation
-------------

There are three main components to PACE:

1. [Encryption][encryption]—Ensuring that data can be read by authorized
parties.
2. [Signatures][signature]—Ensuring that data can only be modified by authorized
parties.
3. [Key management][key-management]—Managing the cryptographic keys necessary
for encryption and signatures to function properly.

Currently, developers can choose to either encrypt **or** sign data. In the
future, we plan to allow users to do both simultaneously.

API
---

The public PACE API is composed of all public types in the following packages:

   * edu.mit.ll.pace
   * edu.mit.ll.pace.encryption
   * edu.mit.ll.pace.signature
   * edu.mit.ll.pace.keymanagement.common

A type is a class, interface, or enum.  Anything with public or protected
acccess in an API type is in the API.  This includes, but is not limited to:
methods, members, classes, interfaces, and enums.  Package-private types in
the above packages are *not* considered public API.

The PACE project maintains binary compatibility across this API within a
major release, as defined in the Java Language Specification 3rd ed. All
API changes will follow [semver 2.0][semver].

Examples
--------
Example code can be found in the examples/simple project. The examples
demonstrate how to generate keys, read and write encrypted/signed data, and
migrate existing tables to use PACE. Descriptions of these examples can be found
in the [examples README][examples].

Building
--------

Accumulo uses [Maven] to compile, test, and package its source.

In addition to the standard Maven lifecycle, the following commands are
supported:

* **apilyzer:analyze**—Analyze the public PACE API, ensuring that it is
[well structured][apilyzer].
* **cobertura:cobertura**–Generates test coverage report in the site directory.
* **javadoc:javadoc**–Generates JavaDoc for the PACE project.

Future Work
-----------
* Key Management—While the [example code][examples] demonstrates how to manually
maintain cryptographic keys, it is not automated, nor does it scale well.
In the future, we plan to add a key management client and server that will
simplify the process of key management.

Troubleshooting
---------------
If you get an `InvalidKeyException: Illegal key size or default parameters`
message, you most likely need to install the Java Cryptography Extension
(JCE) Unlimited Strength Jurisdiction Policy Files. They can be found on
Oracle's website.

Export Control
--------------

This distribution includes cryptographic software. The country in which you
currently reside may have restrictions on the import, possession, use, and/or
re-export to another country, of encryption software. BEFORE using any
encryption software, please check your country's laws, regulations and
policies concerning the import, possession, or use, and re-export of encryption
software, to see if this is permitted. See <http://www.wassenaar.org/> for more
information.

<!--
The U.S. Government Department of Commerce, Bureau of Industry and Security
(BIS), has classified this software as Export Commodity Control Number (ECCN)
5D002.C.1, which includes information security software using or performing
cryptographic functions with asymmetric algorithms. The form and manner of this
Apache Software Foundation distribution makes it eligible for export under the
License Exception ENC Technology Software Unrestricted (TSU) exception (see the
BIS Export Administration Regulations, Section 740.13) for both object code and
source code.
-->

The following provides more details on the included cryptographic software:

PACE uses the built-in Java cryptography libraries in its
encryption implementation. See [Oracle's export-regulations doc][java-export]
for more details on Java's cryptography features. Apache Accumulo also uses
the Bouncy Castle library for some cryptographic technology as well. See
[the Bouncy Castle FAQ][bouncy-faq] for
more details on Bouncy Castle's cryptography features.

Distribution Statement
----------------------

DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.

This material is based upon work supported by the Department of Defense under Air Force Contract No. FA8721-05-C-0002 and/or FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of Defense.

&copy; 2017 Massachusetts Institute of Technology.

The software/firmware is provided to you on an As-Is basis

Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above.

License
-------
Copyright 2017 MIT Lincoln Laboratory
    
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[pace]: https://github.com/mit-ll/pace
[accumulo]: https://accumulo.apache.org
[encryption]: ENCRYPTION.md
[signature]: SIGNATURE.md
[examples]: EXAMPLES.md
[key-management]: KEY_MANAGEMENT.md
[Maven]: https://maven.apache.org
[semver]: http://semver.org/spec/v2.0.0
[java-export]: http://www.oracle.com/us/products/export/export-regulations-345813.html
[bouncy-faq]: http://www.bouncycastle.org/wiki/display/JA1/Frequently+Asked+Questions
[apache]: http://www.apache.org/licenses/
[apilyzer]: https://github.com/revelc/apilyzer-maven-plugin
