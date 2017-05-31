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
package edu.mit.ll.pace.signature;

import edu.mit.ll.pace.IllegalKeyRequestException;

/**
 * Interface for the key container.
 */
public interface SignatureKeyContainer {

  /**
   * Get the signing key to use in signing entries.
   *
   * @return The signing key and an identifier used to retrieve the appropriate verifier key.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  SigningKey getSigningKey();

  /**
   * Get the verifier key for the given signature key.
   *
   * @param id
   *          Id of the signing key used to sign the entry.
   * @return The verifier key to use to verify data signed by the identified signing key.
   * @throws IllegalKeyRequestException
   *           User lacks the permissions to obtain the desired key.
   */
  VerifyingKey getVerifyingKey(byte[] id);

}
