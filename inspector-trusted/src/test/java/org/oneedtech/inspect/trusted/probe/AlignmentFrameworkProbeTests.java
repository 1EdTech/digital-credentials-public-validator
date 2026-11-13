package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class AlignmentFrameworkProbeTests {
  private static final String GOOD =
      "{'targetUrl':'https://example.org/fw/1','targetFramework':'Example Framework'}";

  private Outcome run(String subject) throws Exception {
    return ProbeTestSupport.run(new AlignmentFrameworkProbe(), "{'credentialSubject':" + subject + "}");
  }

  @Test
  void validAlignmentsEverywherePass() throws Exception {
    assertEquals(
        Outcome.VALID,
        run("{'achievement':{'alignment':[" + GOOD + "],'resultDescription':[{'alignment':[" + GOOD
            + "]}]},'result':[{'alignment':[" + GOOD + "]}]}"));
  }

  @Test
  void missingAchievementAlignmentFails() throws Exception {
    assertEquals(Outcome.ERROR, run("{'achievement':{}}"));
  }

  @Test
  void emptyAchievementAlignmentFails() throws Exception {
    assertEquals(Outcome.ERROR, run("{'achievement':{'alignment':[]}}"));
  }

  @Test
  void resultsWithoutAlignmentsPass() throws Exception {
    assertEquals(Outcome.VALID, run("{'achievement':{'alignment':[" + GOOD + "]},'result':[{}]}"));
  }

  @Test
  void nonHttpTargetUrlFails() throws Exception {
    assertEquals(
        Outcome.ERROR,
        run("{'achievement':{'alignment':[{'targetUrl':'urn:uuid:1234','targetFramework':'F'}]}}"));
  }

  @Test
  void relativeTargetUrlFails() throws Exception {
    assertEquals(
        Outcome.ERROR,
        run("{'achievement':{'alignment':[{'targetUrl':'/fw/1','targetFramework':'F'}]}}"));
  }

  @Test
  void missingTargetFrameworkInNestedAlignmentFails() throws Exception {
    assertEquals(
        Outcome.ERROR,
        run("{'achievement':{'alignment':[" + GOOD + "],'resultDescription':[{'alignment':"
            + "[{'targetUrl':'https://example.org/fw/2'}]}]}}"));
  }

  @Test
  void blankTargetFrameworkFails() throws Exception {
    assertEquals(
        Outcome.ERROR,
        run("{'achievement':{'alignment':[{'targetUrl':'https://example.org/fw/1','targetFramework':' '}]}}"));
  }

  @Test
  void alignmentsInEndorsementsAreIgnored() throws Exception {
    assertEquals(
        Outcome.VALID,
        run("{'achievement':{'alignment':[" + GOOD + "],'endorsement':[{'credentialSubject':"
            + "{'alignment':[{'targetUrl':'bad'}]}}]}}"));
  }
}
