package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class CreditsProbeTests {
  private Outcome run(String subject) throws Exception {
    return ProbeTestSupport.run(new CreditsProbe(), "{'credentialSubject':" + subject + "}");
  }

  @Test
  void creditsEarnedOnlyPasses() throws Exception {
    assertEquals(Outcome.VALID, run("{'creditsEarned':3,'achievement':{}}"));
  }

  @Test
  void creditsAvailableOnlyPasses() throws Exception {
    assertEquals(Outcome.VALID, run("{'achievement':{'creditsAvailable':3}}"));
  }

  @Test
  void neitherWarns() throws Exception {
    assertEquals(Outcome.WARNING, run("{'achievement':{}}"));
  }

  @Test
  void creditsAvailableOnSubjectDoesNotCount() throws Exception {
    assertEquals(Outcome.WARNING, run("{'creditsAvailable':3,'achievement':{}}"));
  }
}
