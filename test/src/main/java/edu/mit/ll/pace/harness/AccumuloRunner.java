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
package edu.mit.ll.pace.harness;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.apache.accumulo.core.client.AccumuloException;
import org.apache.accumulo.core.client.AccumuloSecurityException;
import org.junit.runner.Result;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.InitializationError;

/**
 * Run unit tests with an available Accumulo instance.
 */
public final class AccumuloRunner extends BlockJUnit4ClassRunner {

  /**
   * Listener to teardown the Accumulo instance when testing is done.
   */
  private final class AccumuloRunListener extends RunListener {
    @Override
    public void testRunFinished(Result result) throws InterruptedException, IOException {
      AccumuloInstance.teardown();
    }
  }

  /**
   * Instantiate the runner and the Accumulo insance.
   *
   * @param klass
   *          The class that is under test.
   */
  public AccumuloRunner(Class<?> klass) throws InitializationError {
    super(klass);
    try {
      AccumuloInstance.setup();
    } catch (AccumuloException | AccumuloSecurityException | InterruptedException | InvalidKeySpecException | IOException | NoSuchAlgorithmException e) {
      throw new InitializationError(e);
    }
  }

  @Override
  public void run(RunNotifier notifier) {
    notifier.addListener(new AccumuloRunListener());
    super.run(notifier);
  }

}
