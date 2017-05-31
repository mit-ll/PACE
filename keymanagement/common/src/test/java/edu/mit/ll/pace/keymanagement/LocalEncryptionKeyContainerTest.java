/*
 * Copyright 2016 MIT Lincoln Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.mit.ll.pace.keymanagement;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * Unit tests for {@link LocalEncryptionKeyContainer}.
 */
public class LocalEncryptionKeyContainerTest {

  @Rule
  public TemporaryFolder folder = new TemporaryFolder();

  @Test
  public void writeReadTest() throws Exception {
    LocalEncryptionKeyContainer container = new LocalEncryptionKeyContainer();
    container.addKey("a", "b", 1, new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1});
    container.addKey("a", "b", 2, new byte[] {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2});
    container.addKey("d", 3, new byte[] {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3});
    container.addKey("d", 4, new byte[] {4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4});

    File file = folder.newFile();
    FileWriter writer = new FileWriter(file);
    container.write(writer);
    writer.flush();
    writer.close();

    LocalEncryptionKeyContainer container2 = LocalEncryptionKeyContainer.read(new FileReader(file));
    assertThat("has matching keys", container2.getAttributeKey("a", "b", 1, 16), equalTo(container.getAttributeKey("a", "b", 1, 16)));
    assertThat("has matching keys", container2.getAttributeKey("a", "b", 2, 16), equalTo(container.getAttributeKey("a", "b", 2, 16)));
    assertThat("has matching keys", container2.getKey("d", 3, 16), equalTo(container.getKey("d", 3, 16)));
    assertThat("has matching keys", container2.getKey("d", 4, 16), equalTo(container.getKey("d", 4, 16)));
  }

}
