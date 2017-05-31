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

/**
 * Runtime wrapper for exceptions that occur during signing.
 */
public class SignatureException extends RuntimeException {

  private static final long serialVersionUID = 3546537933578657569L;

  /**
   * Constructs a new signature exception with null as its detail message.
   */
  public SignatureException() {
    super();
  }

  /**
   * Constructs a new signature exception with the specified detail message.
   *
   * @param message
   *          the detail message. The detail message is saved for later retrieval by the {@link Throwable#getMessage()} method.
   */
  public SignatureException(String message) {
    super(message);
  }

  /**
   * Constructs a new signature exception with the specified cause and a detail message of (cause==null ? null : cause.toString()) (which typically contains the
   * class and detail message of cause). This constructor is useful for runtime exceptions that are little more than wrappers for other throwables.
   *
   * @param cause
   *          the cause (which is saved for later retrieval by the {@link Throwable#getCause()} method). (A null value is permitted, and indicates that the
   *          cause is nonexistent or unknown.)
   */
  public SignatureException(Throwable cause) {
    super(cause);
  }

  /**
   * Constructs a new signature exception with the specified detail message and cause.
   * <p>
   * Note that the detail message associated with cause is not automatically incorporated in this runtime exception's detail message.
   *
   * @param message
   *          the detail message. The detail message is saved for later retrieval by the {@link Throwable#getMessage()} method.
   * @param cause
   *          the cause (which is saved for later retrieval by the {@link Throwable#getCause()} method). (A null value is permitted, and indicates that the
   *          cause is nonexistent or unknown.)
   */
  public SignatureException(String message, Throwable cause) {
    super(message, cause);
  }
}
