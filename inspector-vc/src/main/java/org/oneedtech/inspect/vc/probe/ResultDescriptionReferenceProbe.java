package org.oneedtech.inspect.vc.probe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A Probe that checks that every result description reference in the credential subject's
 * results resolves to the id of a result description in the asserted achievement.
 *
 * <p>Results without a {@code resultDescription} are ignored. References are compared to ids by
 * exact string match.
 */
public class ResultDescriptionReferenceProbe extends Probe<JsonNode> {

  public ResultDescriptionReferenceProbe() {
    super(ID, TITLE);
  }

  @Override
  public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
    JsonNode subject = root.get("credentialSubject");
    if (subject == null || !subject.hasNonNull("result")) {
      return success("No results in credentialSubject", ctx);
    }

    Set<String> resultDescriptionIds = new HashSet<>();
    JsonNode achievement = subject.get("achievement");
    if (achievement != null && achievement.hasNonNull("resultDescription")) {
      for (JsonNode resultDescription :
          JsonNodeUtil.asNodeList(achievement.get("resultDescription"))) {
        JsonNode id = resultDescription.get("id");
        if (id != null && id.isTextual()) {
          resultDescriptionIds.add(id.textValue());
        }
      }
    }

    List<String> unresolved = new ArrayList<>();
    List<JsonNode> results = JsonNodeUtil.asNodeList(subject.get("result"));
    for (int i = 0; i < results.size(); i++) {
      JsonNode reference = results.get(i).get("resultDescription");
      if (reference == null || reference.isNull()) continue;
      String value = reference.asText();
      if (!resultDescriptionIds.contains(value)) {
        unresolved.add(
            "result["
                + i
                + "].resultDescription \""
                + value
                + "\" does not match any resultDescription id in achievement");
      }
    }

    if (!unresolved.isEmpty()) {
      return error(
          "Unresolved result description reference(s) in credentialSubject: "
              + String.join("; ", unresolved),
          ctx);
    }
    return success("All result description references resolve", ctx);
  }

  public static final String ID = ResultDescriptionReferenceProbe.class.getSimpleName();
  public static final String TITLE = "Verification of result description references";
}
