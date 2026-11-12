package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class AchievedLevelProbeTests {
  private static final String ACHIEVEMENT =
      "'achievement':{'resultDescription':["
          + "{'id':'urn:rd:rubric','rubricCriterionLevel':[{'id':'urn:lvl:1'},{'id':'urn:lvl:2'}]},"
          + "{'id':'urn:rd:empty','rubricCriterionLevel':[]},"
          + "{'id':'urn:rd:plain'}]}";

  private Outcome run(String results) throws Exception {
    return ProbeTestSupport.run(
        new AchievedLevelProbe(), "{'credentialSubject':{" + ACHIEVEMENT + ",'result':" + results + "}}");
  }

  @Test
  void matchingAchievedLevelPasses() throws Exception {
    assertEquals(Outcome.VALID, run("[{'resultDescription':'urn:rd:rubric','achievedLevel':'urn:lvl:2'}]"));
  }

  @Test
  void missingAchievedLevelFails() throws Exception {
    assertEquals(Outcome.ERROR, run("[{'resultDescription':'urn:rd:rubric'}]"));
  }

  @Test
  void unknownAchievedLevelFails() throws Exception {
    assertEquals(Outcome.ERROR, run("[{'resultDescription':'urn:rd:rubric','achievedLevel':'urn:lvl:9'}]"));
  }

  @Test
  void descriptionWithoutLevelsPasses() throws Exception {
    assertEquals(Outcome.VALID, run("[{'resultDescription':'urn:rd:plain'},{'resultDescription':'urn:rd:empty'}]"));
  }

  @Test
  void unresolvedReferenceIsSkipped() throws Exception {
    assertEquals(Outcome.VALID, run("[{'resultDescription':'urn:rd:unknown'}]"));
  }

  @Test
  void resultWithoutReferenceIsSkipped() throws Exception {
    assertEquals(Outcome.VALID, run("[{'value':'A'}]"));
  }

  @Test
  void noResultsPass() throws Exception {
    assertEquals(Outcome.VALID, ProbeTestSupport.run(new AchievedLevelProbe(), "{'credentialSubject':{}}"));
  }
}
