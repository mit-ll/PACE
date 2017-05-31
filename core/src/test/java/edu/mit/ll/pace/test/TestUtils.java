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
package edu.mit.ll.pace.test;

import java.io.IOException;
import java.io.InputStream;

/**
 * Functions utilized across the tests.
 */
public final class TestUtils {

  /**
   * Get a resource for the given class.
   *
   * @param clazz
   *          Class to get the resource for.
   * @param resourceName
   *          THe name of the resource.
   * @return An stream to the resource.
   * @throws IOException
   *           Thrown if the resource name does not exist.
   */
  public static InputStream getResourceAsStream(Class<?> clazz, String resourceName) throws IOException {
    if (resourceName.startsWith("/")) {
      return clazz.getResourceAsStream(resourceName);
    }

    InputStream resource = clazz.getResourceAsStream(clazz.getSimpleName() + "/" + resourceName);
    if (resource == null) {
      resource = clazz.getResourceAsStream(resourceName);
    }
    return resource;
  }

  /**
   * Wrap a byte[] in a Byte[] so that it can be used with {@link org.hamcrest.Matchers#arrayContaining(Object[])} )}.
   *
   * @param data
   *          Data to be wrapped.
   * @return Wrapped array.
   */
  public static Byte[] wrap(byte[] data) {
    Byte[] newData = new Byte[data.length];
    for (int i = 0; i < data.length; i++) {
      newData[i] = data[i];
    }
    return newData;
  }

}
