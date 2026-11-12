package org.oneedtech.inspect.vc.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.OB30Inspector;
import org.oneedtech.inspect.vc.Samples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ResultDescriptionReferenceProbeTests {

  private final ObjectMapper mapper = new ObjectMapper();

  private boolean run(String subject) throws Exception {
    JsonNode root = mapper.readTree("{\"credentialSubject\":" + subject + "}");
    ReportItems items =
        new ResultDescriptionReferenceProbe().run(root, new RunContext.Builder().put(new OB30Inspector.Builder().build())
                .put(Samples.OB30.JSON.SIMPLE_JSON.asFileResource())
                .build());
    return items.asBoolean();
  }

  @Test
  void resolvedReferencesPass() throws Exception {
    assertEquals(
        true,
        run(
            "{\"achievement\":{\"resultDescription\":[{\"id\":\"urn:a\"},{\"id\":\"urn:b\"}]},"
                + "\"result\":[{\"resultDescription\":\"urn:b\"},{\"resultDescription\":\"urn:a\"}]}"));
  }

  @Test
  void resultsWithoutReferencePass() throws Exception {
    assertEquals(true, run("{\"achievement\":{},\"result\":[{\"value\":\"A\"}]}"));
  }

  @Test
  void noResultsPass() throws Exception {
    assertEquals(true, run("{\"achievement\":{}}"));
  }

  @Test
  void unknownReferenceFails() throws Exception {
    assertEquals(
        false,
        run(
            "{\"achievement\":{\"resultDescription\":[{\"id\":\"urn:a\"}]},"
                + "\"result\":[{\"resultDescription\":\"urn:a\"},{\"resultDescription\":\"urn:x\"}]}"));
  }

  @Test
  void referenceWithoutAchievementDescriptionsFails() throws Exception {
    assertEquals(false, run("{\"achievement\":{},\"result\":[{\"resultDescription\":\"urn:a\"}]}"));
  }

  @Test
  void comparisonIsExact() throws Exception {
    assertEquals(
        false,
        run(
            "{\"achievement\":{\"resultDescription\":[{\"id\":\"urn:A\"}]},"
                + "\"result\":[{\"resultDescription\":\"urn:a\"}]}"));
  }
}
