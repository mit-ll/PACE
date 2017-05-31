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

Key Management
--------------
In PACE there are two types of keys, symmetric encryption keys (e.g., AES) and
asymmetric signature keys (e.g., RSA). While PACE defines the structure of these
keys (e.g., key length) it is left to the developers to generate, distribute, 
and manage the keys.

While we plan to provide an example key management server
and client in the future, these are not currently implemented. In the meantime,
the [examples][examples], which provide basic key management operations, can be
used  as templates to define your own key management framework. These
examples make use of locally stored key containers, which can be used
by importing the following artifact:

```xml
<dependency>
  <groupId>edu.mit.ll.pace</groupId>
  <artifactId>pace-keymanagement-common</artifactId>
  <version>1.0.0</version>
</dependency>
```

[examples]: EXAMPLES.md
