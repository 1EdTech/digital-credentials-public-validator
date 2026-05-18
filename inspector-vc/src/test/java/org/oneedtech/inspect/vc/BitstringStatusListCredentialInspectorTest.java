package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.assertValid;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;

public class BitstringStatusListCredentialInspectorTest {
  private static BitstringStatusListCredentialInspector validator;
  private static boolean verbose = true;

  @BeforeAll
  static void setup() {
    validator =
        new BitstringStatusListCredentialInspector.Builder()
            .set(Behavior.TEST_INCLUDE_SUCCESS, true)
            .set(Behavior.VALIDATOR_FAIL_FAST, true)
            .build();
  }

  @Test
  void testSimpleJsonValid() {
    assertDoesNotThrow(
        () -> {
          Report report =
              validator.run(Samples.OB30.BSL.SIMPLE_JSON.asFileResource(ResourceType.JSON));
          if (verbose) PrintHelper.print(report, true);
          assertValid(report);
        });
  }

  @Test
  void testIssue52() {
    assertDoesNotThrow(
        () -> {
          URI statusListCredentialUrl =
              new URI(
                  "https://rwa.uwidev.udisp8.di-uisp-accenture.com/acnid.a7ee508a-1020-427e-9c0a-ed4739a49a52.credential-status.dde4729ecfe76886324ae507e85e0f871d045f119152668f6d422a6c99ff2f20");
          UriResource uriResource =
              new UriResource(
                  statusListCredentialUrl,
                  null,
                  List.of(
                      ResourceType.VC_JSON_LD,
                      ResourceType.JSON_LD,
                      ResourceType.JSON,
                      ResourceType.VC_JWT,
                      ResourceType.JWT));

          Report report = validator.run(uriResource);
          if (verbose) PrintHelper.print(report, true);
          assertValid(report);
        });
  }
}
