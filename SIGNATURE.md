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

Integrity
---------

The signature code allows clients to sign data before storing it at the server.
This prevents data from being modified by the server administrator.

The signature code is designed as a drop-in replacement for Accumulo's
BatchWriter, BatchScanner, and Scanner classes. It can be configured
programmatically or through the use of configuration files (preferred).
Cryptographic keys are provided by the developer (see
[key management][key-management]).

API
---

Classes for signature functionality are found in
`edu.mit.ll.pace.signature`.

#### `SignedBatchWriter`

The signed batch writer is created similarly to a `BatchWriter`. After creation,
it is used identically to the Accumulo `BatchWriter`.

```java
BatchWriter writer = new SignedBatchWriter(
    instance.getConnector(),
    TABLE_NAME,
    batchWriterConfig,
    signatureConfig,
    signatureKey);
```

#### `SignedBatchScanner`

The signed batch scanner is created similarly to a `BatchScanner`. After
creation, it is used identically to the Accumulo `BatchScanner`.

```java
BatchScanner scanner = new SignedBatchScanner(
    instance.getConnector(),
    TABLE_NAME,
    authorizations,
    numThreads,
    signatureConfig,
    verificationKeys);
```

#### `SignedScanner`

The signed batch scanner is created similarly to a `Scanner`. After creation,
it is used identically to the Accumulo `Scanner`.

```java
Scanner scanner = new SignedScanner(
    instance.getConnector(),
    TABLE_NAME,
    authorizations,
    signatureConfig,
    verificationKeys);
```

Configuration
-------------

The configuration for the signature code is given by a `SignatureConfig` object.
This configuration object can be created programmatically or loaded from a
configuration file.

The configuration files specify the signature algorithm that will be used to
sign entries.

```ini
[Signature]
algorithm = {RSA-PKCS1,RSA-PSS,DSA,ECDSA}
provider = {SunJCE,BC,...}
```

Example config files can be found in the resources folder
(`edu.mit.ll.pace.signature`).

#### algorithm
Dictates the algorithm to use for signing and verifying records. The following
algorithms are available for signing and verifying data.

* **RSA-PKCS1**–RSA signature using the old PKCS #1 v1.5 padding.
* **RSA-PSS**–RSA signature using the more modern PSS padding scheme.
* **DSA**—DSA signature.
* **ECDSA**—ECDSA signature.

All algorithms sign the SHA256 hash of the data. BouncyCastle is required for
using RSA-PSS and DSA.

##### provider (Optional)
The Java cryptographic provider to use. If not set, will let the system decide
the appropriate cryptographic provider.

Compatibility Options (Use with Care)
-------------------------------------

By default, the signature is stored in the value field. When using the PACE
classes, this signature is verified and stripped before the value is returned.
In some cases, it may be necessary to sign data, while still allowing older,
non-PACE aware clients to continue accessing the data. In this case, we have
provided two alternative locations to store the signature.

##### Storing signatures in the columnVisibility field
The signature can be stored in the column visibility field by adding it as a
disjunctive clause (i.e., `(originalVisibility)|encodedSignature`). This is
done by adding the following two lines to the configuration file:

```ini
[Signature]
destination = colVis
defaultVisibility = ...
```

As with the default behavior, PACE clients will strip the signature from the
column visibility field before returning the data. Non-PACE aware clients will
see the signature, but will ignore it as it will be a visibility label for which
no user will have access.

The `defaultVisibility` option specifies what the default visibility field is
for the table where signatures will be stored. This is used when the entry being
 signed has an empty visibility field.

**Limitations:**

1. Storing signatures in the column visibility field breaks versioning. As such,
it should only be used with tables that do not rely on Accumulo to version
entries.
2. The `SignedBatchWriter` is unable to delete entries when the signature is
stored in the column visibility field.

##### Storing signatures in a separate table
The signature can also be stored in a separate table. This is done by adding the
following two lines to the configuration file:

```ini
destination = table
table = ...
```

In this case, signatures are stored in a second, duplicate table, where the
values are replaced with signatures. The name of this second table is given in
the configuration.

**Limitations:**

1. This approach is much slower. First, it requires two tables to be scanned.
Second, if the data in the two tables is retrieved out of order
(i.e., batch scanning), an internal copy of all signatures that have not yet
been matched must be kept, increasing the memory requirements.
2. This option requires that both tables are versioned, and cannot be used if
versioning is disabled.


[key-management]: KEY_MANAGEMENT.md
