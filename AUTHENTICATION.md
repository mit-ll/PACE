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

Authentication
---------------
The authentication code implements a SkipList: a probabilistic data structure
designed for fast (O(log n)) searching over an ordered data set. This code
lays the groundwork for the capability to authenticate query results - i.e.,
to verify that the server has not modified or deleted data and that the
results it returns to search and range queries are accurate. This functionality
requires the use of an AuthenticatedSkipList, which extends the basic SkipList
construction by attached labels to each node that contain hashes based on
all of that node's children. A modification or removal of any node is detectable
in an AuthenticatedSkipList, because the labels of that node's antecedents will
be affected.

The provided code implements a SkipList in a way that provides hooks for the
authentication layer, but the authentication layer itself is not implemented.
It is our hope that if the community desires query authentication functionality,
they will be able to extend this code for that purpose.

Functionality
---
Classes for SkipList functionality are found in `edu.mit.ll.pace.authentication`.

#### `SkipList`

A `SkipList` can be created by calling the constructor; elements are inserted using
the `insert` method. Elements are of the type `SkipListElement`, which contains a
key and a hash value.

```java
SkipList list = new SkipList();
SkipListElement APPLE = new SkipListElement(
                            new Key(new Text("Apple")),
                            new byte[] {1});
list.insert(APPLE);
```

The list can be searched for a given key using the `search` method. This method
returns a `SkipListSearchTrace` encapsulating the node found by the search and
an ordered list containing each element traversed while searching and each of
those elements' neighbors, which are used in the query verification process.

```java
SkipListSearchTrace trace = list.search(APPLE.key);
if (trace.success()){
    SkipListNode foundNode = trace.getFound();
}
```

The `SkipListSearchTrace` consists of `TraceItem`s, containing the node along
with a label identifying its type:
* **`TRAVERSED`**—A node traversed on the search path.
* **`RIGHT_BOUNDARY`**—A node whose value was checked and determined to be greater
than the search value, resulting in a downward traversal.
* **`DOWN_BOUNDARY`**—A node that was not traversed but that is the downward
neighbor of a traversed node. This type of node is added to the trace before
a rightward traversal.
* **`RESULT`**—The node that was searched for. This type is only added if the
search was successful.
* **`ANTERIOR`**—The last node whose value is less than the node that was
searched for. This type is only added if the search was unsuccessful.

This trace provides the information necessary to verify the server's response
to a search query.

A `SkipListRangeQueryTrace` object is created with a similar structure when the
`inclusiveRange` method is called.

```java
SkipListRangeQueryTrace trace = list.inclusiveRange(APPLE.key, DAIKON.key);
if (trace.success()){
    Collection<SkipListNode> foundNodes = trace.getFound();
}
```

Extending for Authentication
---
To extend the SkipList for query authentication, the algorithms for verifying
the `SkipListSearchTrace` and `SkipListRangeQueryTrace` must be
implemented. Additionally, the client must store the basis of the SkipList:
the label of the root (top-right) node. When a trace is verified, the verified basis
must be compared against the stored basis. The stored basis must be updated
when an authenticated insertion is performed; this update can be done using
the information contained in the `SkipListSearchTrace` returned by the
`insert` method.

Details regarding how to implement this functionality are provided in
"Implementation of an authenticated dictionary with skip lists and commutative hashing",
Goodrich et. al., DISCEX '01

