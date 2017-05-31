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
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Functions utilized across the tests.
 */
public final class TestUtils {

  /**
   * The charset used to serialize data to Accumulo.
   */
  public static final Charset CHARSET = StandardCharsets.UTF_8;

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

}
