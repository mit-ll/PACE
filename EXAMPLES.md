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

Examples
--------
In the `examples/simple` module we have included several examples that show
how to use the PACE library for encryption and signatures:

* Encryption
  * GenerateEncryptionKeys—Demonstrates how encryption keys can be managed from
  the command line.
  * EncryptedReadWriteExample—Modified
  `org.apache.accumulo.examples.simple.client.ReadWriteExample`; demonstrates
  how to write, then read, encrypted data.
  * EncryptedConverterExample—Converts an existing unencrypted table into an
  encrypted table.
* Signature
  * GenerateSignatureKeys—Demonstrates how signature keys can be managed from
  the command line.
  * SignedReadWriteExample—Modified
  `org.apache.accumulo.examples.simple.client.ReadWriteExample`; demonstrates
  how to write, then, read, signed data.
  * SignedConverterExample—Converts an existing unsigned table into a signed
  table.

We describe below how to use these samples to generate keys, convert an existing
table to one that is signed/encrypted, and read data from that table.
 
To prepare to run the following examples, first set up the environment as
follows:

```bash
cd examples/simple
mvn clean compile
mkdir -p target/keys
```

Encryption
----------

### Key generation

First we will generate three encryption keys and put them into a key store for
later use:

1. An encryption key for AES_GCM.
2. An encryption key for AES_GCM when the visibility label is `secret`.
3. An encryption key for AES_GCM when the visibility label is `default`.

```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.GenerateEncryptionKeys -Dexec.args="--master-key-file target/keys/master.keys --write-master-key --key AES_GCM --key AES_GCM|secret --key AES_GCM|default --store target/keys/enc.keys"
```

The master secret file stores a randomly generated master secret that is used
in the generation of all encryption keys. The master secret file is needed in
order to generate more keys later. For example, the following command creates a
second encryption key store that has keys 1 and 3 from the first key store, but
not key 2.

```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.GenerateEncryptionKeys -Dexec.args="--master-key-file target/keys/master.keys --read-master-key --key AES_GCM --key AES_GCM|default --store target/keys/enc3.keys"
```

### Converting Data
First we will use an example from Accumulo to create data in a table:

```bash
$ACCUMULO_HOME/bin/accumulo org.apache.accumulo.examples.simple.client.ReadWriteExample -i instance -z zookeepers -u user -p password --table test --createtable --create --auths secret,default
```

Now we will convert that data into encrypted form:
```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.EncryptedConverterExample -Dexec.args="-i instance -z zookeepers -u user -p password --source test --destination test2 --createtable --encryption-config ../../core/src/main/resources/edu/mit/ll/pace/encryption/encrypt-value.ini --encryption-keys target/keys/enc.keys --auths secret,default"
```

In the Accumulo shell you can view the encrypted data:
```bash
table test2
scan
```

### Reading Data
Next we will read the data in its unencrypted form:

```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.EncryptedReadWriteExample -Dexec.args="-i instance -z zookeepers -u user -p password --table test2 --read --encryption-config ../../core/src/main/resources/edu/mit/ll/pace/encryption/encrypt-value.ini --encryption-keys target/keys/enc.keys --auths secret,default"
```


Signatures
----------

### Key generation

First we will generate an RSA signature and verification keys for two users,
Alice and Bob.

The following command will create a key store for Alice (containing Alice's
generated private and public RSA key):

```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.GenerateSignatureKeys -Dexec.args="--key Alice|RSA|2048 --key-dir target/keys --public-key-file target/keys/public.keys"
```

Later Bob's key store is created (containing Bob's generated public and private
keys, and Alice's public key). Alice's key store is also updated to included
Bob's public key:
```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.GenerateSignatureKeys -Dexec.args="--key Bob|RSA|2048 --key-dir target/keys --public-key-file target/keys/public.keys --update"
```


### Converting Data
First we will use an example from Accumulo to create data in a table:

```bash
$ACCUMULO_HOME/bin/accumulo org.apache.accumulo.examples.simple.client.ReadWriteExample -i instance -z zookeepers -u user -p password --table test3 --createtable --create --auths secret,default
```

Now we will convert that data into signed form:
```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.SignatureConverterExample -Dexec.args="-i instance -z zookeepers -u user -p password --source test3 --destination test4 --createtable --signature-config ../../core/src/main/resources/edu/mit/ll/pace/signature/rsa.ini --signature-keys target/keys/Alice_RSA.keys --auths secret,default"
```

In the Accumulo shell you can check that the data is signed:
```bash
table test4
scan
```

### Reading Data
Next we will read the data, verifying its signature. We use Bob's key store to
demonstrate that different users can verify signatures, as long as they have the
appropriate public key.

```
mvn exec:java -Dexec.mainClass=edu.mit.ll.pace.examples.simple.SignedReadWriteExample -Dexec.args="-i instance -z zookeepers -u user -p password --table test4 --read --signature-config ../../core/src/main/resources/edu/mit/ll/pace/signature/rsa.ini --signature-keys target/keys/Bob_RSA.keys --auths secret,default"
```
