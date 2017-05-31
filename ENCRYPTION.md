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

Confidentiality
---------------

The encryption code allows clients to encrypt data before storing it at the
server. This prevents that data from being read by the server administrator.
Additionally, it can be used to cryptographically enforce visibility labels.

The encryption code is designed as a drop-in replacement for Accumulo's
BatchWriter and BatchScanner classes. It can be configured programmatically
or through the use of configuration files (preferred). Cryptographic keys
are provided by the developer (see [key management][key-management]).

API
---

Classes for encryption functionality are found in `edu.mit.ll.pace.encryption`.

#### `EncryptedBatchWriter`

The encrypted batch writer is created similarly to a `BatchWriter`. After
creation, it is used identically to the Accumulo `BatchWriter`.

```java
BatchWriter writer = new EncryptedBatchWriter(
    instance.getConnector(),
    TABLE_NAME,
    batchWriterConfig,
    encryptionConfig,
    encryptionKeys);
```

#### `EncryptedBatchScanner`

The encrypted batch scanner is created similarly to a `BatchScanner`. After
creation, it is used identically to the Accumulo `BatchScanner`.

```java
BatchScanner scanner = new EncryptedBatchScanner(
    instance.getConnector(),
    TABLE_NAME,
    authorizations,
    numThreads,
    encryptionConfig,
    encryptionKeys);
```

Configuration
-------------

The encryption configuration defines which fields will be encrypted, and with
which modes of operation. The encryption configuration of each field can be set
separately from the other fields. This configuration is given by an
`EncryptionConfig` object. These configuration objects can be created
programmatically or loaded from a configuration file.

The configuration file is split into sections, one for each field that will
store encrypted data. The layout of these sections is as follows:

```ini
[{row, columnFamily, columnQualifier, value}]
cipher = {AES_CTR, AES_CFB, AES_CBC, AES_OFB, AES_GCM, AES_SIV_DETERMINISTIC}
provider = {SunJCE,BC,...}
useVisibility = {true,false}
keyId = {keyId}
keyLength = {16, 24, 32, ...}
sources = {row, columnFamily, columnQualifier, columnVisibility, value}
```

##### Section Header
The section header defines which field will store the encrypted data.

##### cipher
Dictates the algorithm, mode, and padding to use for encryption. The various
modes fall into the following
three categories:

1. Semantically secure encryption—Encrypted data reveals no partial information
about the plaintext data (other than length). In particular, encryption does not
reveal equalities of plaintexts; for a given key, encrypting the same value
repeatedly will produce different ciphertexts. This prevents a server
administrator from detecting patterns in the data.
2. Authenticated encryption—In addition to providing confidentiality with
semantic security, authenticated encryption provides integrity and authenticity,
meaning that any unauthorized changes to the data will be detected.
3. Deterministic encryption—For a given key, encrypting the same value
repeatedly will always produce the same ciphertext. This allows for encrypted
data to be searched for server-side but also allows the server administrator to
detect patterns in the data (see https://cs.brown.edu/~seny/pubs/edb.pdf).
**For this reason, care should be taken when using this type of encryption**,
and it should only be used when the performance gains are more important than
the loss of security.

The following ciphers are available for use in encryption.

* **AES_CTR**—Semantically secure—Encrypts data using AES in CTR mode with no
padding.
* **AES_CFB**—Semantically secure—Encrypts data using AES in CFB mode with no
padding.
* **AES_CBC**—Semantically secure—Encrypts data using AES in CBC mode with PKCS5
 padding.
* **AES_OFB**—Semantically secure—Encrypts data using AES in OFB mode with no
padding.
* **AES_GCM**—Authenticated—Encrypts data using AES in GCM mode with no padding.
* **AES_SIV_DETERMINISTIC**—Deterministic—Encrypts data using AES in SIV mode
with no padding.

If unsure, we recommend the use of AES_GCM. It is very important to note that
the GCM encryption key must be refreshed to limit the number of GCM encryptions
with a given key in order to prevent IV reuse; similarly for CTR mode. The NIST
recommendation (SP 800-38 D) is to limit the number of invocations of encryption
with GCM for any given key to 2^32.

##### provider (Optional)
The Java cryptographic provider to use. If not set, will let the system decide
the appropriate cryptographic provider.

##### useVisibility (Optional, default=false)
Whether to use encryption to enforce the column visibility field. If this is set
to true, only users that have encryption keys corresponding to the appropriate
labels in the column visibility field will be able to decrypt the data. For
example, if the visibility is `doctor | (nurse & admin)`, a user with only the
doctor attribute key will be able to decrypt the row, but a user with only the
nurse key (and neither the doctor key nor the admin key) will not be able to
decrypt.

When writing data, there is currently a limitation that requires the client to
have keys for  all labels in the visibility field. In the above example, the
user would need to have the doctor, nurse, **and** admin attribute keys to
encrypt the row. We are looking to address this limitation in future versions of
the code base.

##### keyId (Optional, default=cipher)
An identifier for the keys used to encrypt the field. This value is passed to
the key management interface to specify which key to retrieve. If not set, will
use the value given in the cipher field.

##### keyLength (Optional, default=16|32)
The length of the key to use for encryption, in bytes. This is one of {16, 24,
32} for non-deterministic encryption ciphers, and {32, 48, 64} for deterministic
 encryption ciphers. If not set, will use the smallest appropriate key length.

##### sources (Optional, default=section header)
The source of the data that should be encrypted into the field. If not set, the
encrypted data will be drawn from the same field as the encrypted.

Example configurations
----------------------

Within the core library's jar resources there are three example configurations
(`edu/mit/ll/place/encryption`). 
These demonstrate some configurations that should support a large number of use
cases. 

* **encrypt-value**—Encrypts the value using AES in GCM mode, with the
encryption cryptographically enforcing the column visibility.
* **encrypt-entry**—Encrypts each field in the entry (row, columnFamily,
columnQualifier, value) individually using AES in GCM mode, with the encryption
cryptographically enforcing the column visibility.
* **searchable**—Encrypts each field in the entry key (row, columnFamily,
columnQualifier) individually using AES in SIV mode (deterministic encryption),
with the encryption not being used to enforce column visibility. The value is
encrypted using AES in GCM mode, with the encryption cryptographically enforcing
the column visibility. Since the key is encrypted deterministically, the system
can still search for records server-side.

Limitations
-----------

1. If any field in the key is encrypted with non-deterministic encryption,
Accumulo versioning on the table will be broken.
1. If any field in the key is encrypted with non-deterministic encryption, it is
not possible for the `EncryptedBatchWriter` to delete values. Instead it is
necessary to delete keys using an `ItemProcessingIterator`:
    ```java
    EncryptedBatchScanner encryptedBatchScanner = ...;
    BatchWriter writer = ...;
    ItemProcessingIterator<Entry<Key,Value>> iterator = encryptedBatchScanner.iterator();

    while (iterator.hasNext()) {
      if (isKeyToDelete(iterator.next())) {
        Entry<Key,Value> unprocessed = iterator.unprocessed();
        Mutation delete = new Mutation(unprocessed.getKey().getRow());
        delete.putDelete(unprocessed.getKey().getColumnFamily(), unprocessed.getKey().getColumnQualifier(), unprocessed.getKey().getColumnVisibilityParsed(),
            unprocessed.getKey().getTimestamp());
      }
    }
    writer.close();
    ```
1. If the entry key is encrypted deterministically and one of the encryption
keys is revoked—resulting in a new version of the encryption key—then entries
created with the new key will not version correctly with entries created with
the old key. Both sets of entries will show up in the scanner.
1. When attempting to filter results returned by `EncryptedBatchScanner`, if
possible, the filtering will happen server side. In several situations it is
necessary to still filter some of the data client side:
    1. If any of the search fields (e.g., row, column family) are encrypted
    non-deterministially, than those field must be filtered client side.
    2. If a contents of a search field are encrypted into another field (e.g.,
    row encrypts both the row and column family, leaving the column family
    zeroed out), then the field can only be filtered server side if the
    encrypted field containing it is also part of the search (e.g., searching
    using a range will work, but not searching using `fetchColumnFamily`).
    3. For a deterministically encrypted field, the search must be a single
    value and not a range of values. Similarly, fields preceding the encrypted
    field must be a single value and not a range of values. Fields after the
    encrypted field can be searched over a range. (e.g., if the column family is
    encrypted, you can only create ranges that have the same row and column
    family, but the column qualifier can be multiple values.)

[key-management]: KEY_MANAGEMENT.md
