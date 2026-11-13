package org.oneedtech.inspect.trusted;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;

public class TrustedCredentialTypeTests {
  private static final String W3C = "'https://www.w3.org/ns/credentials/v2'";
  private static final String OB = "'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'";
  private static final String EXT = "'" + TrustedCredentialType.OB_EXTENSIONS_CONTEXT + "'";
  private static final String TRUSTED = "'" + TrustedCredentialType.TRUSTED_CONTEXT + "'";

  private static Outcome check(String... contexts) throws Exception {
    String json = ("{'@context':[" + String.join(",", contexts) + "]}").replace('\'', '"');
    RunContext ctx =
        new RunContext.Builder().put(new TrustedCredentials10Inspector.Builder().build())
            .put(Samples.TRUSTED.VALID.asFileResource(ResourceType.JSON))
            .build();
    return new ContextPropertyProbe(TrustedCredentialType.INSTANCE)
        .run(new ObjectMapper().readTree(json), ctx)
        .getOutcome();
  }

  @Test
  void requiredContextsInOrderPass() throws Exception {
    assertEquals(Outcome.VALID, check(W3C, OB, EXT, TRUSTED));
  }

  @Test
  void extraContextsAfterRequiredOnesPass() throws Exception {
    assertEquals(
        Outcome.VALID,
        check(W3C, OB, EXT, TRUSTED, "'https://purl.imsglobal.org/spec/ob-accred/v2p0/context'"));
  }

  @Test
  void obContextAliasesStillApply() throws Exception {
    assertEquals(
        Outcome.WARNING,
        check(W3C, "'https://purl.imsglobal.org/spec/ob/v3p0/context.json'", EXT, TRUSTED));
  }

  @Test
  void misorderedContextsAreErrors() throws Exception {
    assertEquals(Outcome.ERROR, check(W3C, OB, TRUSTED, EXT));
  }

  @Test
  void missingContextsAreErrors() throws Exception {
    assertEquals(Outcome.ERROR, check(W3C, OB, EXT));
    assertEquals(Outcome.ERROR, check(W3C, OB));
  }

  @Test
  void trustedContextMatchesExactly() throws Exception {
    assertEquals(Outcome.ERROR, check(W3C, OB, EXT, TRUSTED.replace("context.json", "context.json/")));
  }
}
