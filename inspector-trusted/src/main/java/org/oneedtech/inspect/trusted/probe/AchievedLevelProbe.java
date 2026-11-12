package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * Checks that every Result whose referenced Result Description defines rubric criterion levels
 * includes an {@code achievedLevel}, and that it matches the id of one of those levels.
 *
 * <p>Results without a Result Description Reference, or whose reference does not resolve, are
 * skipped: unresolved references are reported by the OB 3.0 ResultDescriptionReferenceProbe.
 */
public class AchievedLevelProbe extends Probe<VerifiableCredential> {

  public AchievedLevelProbe() {
    super(ID, TITLE);
  }

  @Override
  public ReportItems run(VerifiableCredential credential, RunContext ctx) throws Exception {
    JsonNode subject = credential.getJson().get("credentialSubject");
    if (subject == null || !subject.hasNonNull("result")) {
      return success("No results in credentialSubject", ctx);
    }

    Map<String, Set<String>> levelsByDescription = new HashMap<>();
    JsonNode achievement = subject.get("achievement");
    if (achievement != null && achievement.hasNonNull("resultDescription")) {
      for (JsonNode description : JsonNodeUtil.asNodeList(achievement.get("resultDescription"))) {
        JsonNode id = description.get("id");
        if (id == null || !id.isTextual()) continue;
        Set<String> levels = new HashSet<>();
        if (description.hasNonNull("rubricCriterionLevel")) {
          for (JsonNode level : JsonNodeUtil.asNodeList(description.get("rubricCriterionLevel"))) {
            JsonNode levelId = level.get("id");
            if (levelId != null && levelId.isTextual()) levels.add(levelId.textValue());
          }
        }
        levelsByDescription.put(id.textValue(), levels);
      }
    }

    List<String> problems = new ArrayList<>();
    List<JsonNode> results = JsonNodeUtil.asNodeList(subject.get("result"));
    for (int i = 0; i < results.size(); i++) {
      JsonNode result = results.get(i);
      JsonNode reference = result.get("resultDescription");
      if (reference == null || reference.isNull()) continue;
      Set<String> levels = levelsByDescription.get(reference.asText());
      if (levels == null || levels.isEmpty()) continue;

      JsonNode achievedLevel = result.get("achievedLevel");
      if (achievedLevel == null || achievedLevel.isNull()) {
        problems.add(
            "result["
                + i
                + "] must include achievedLevel because its resultDescription \""
                + reference.asText()
                + "\" defines rubricCriterionLevel");
      } else if (!levels.contains(achievedLevel.asText())) {
        problems.add(
            "result["
                + i
                + "].achievedLevel \""
                + achievedLevel.asText()
                + "\" does not match any rubricCriterionLevel id in resultDescription \""
                + reference.asText()
                + "\"");
      }
    }

    if (!problems.isEmpty()) {
      return error(String.join("; ", problems), ctx);
    }
    return success("All results with rubric criterion levels have a valid achievedLevel", ctx);
  }

  public static final String ID = AchievedLevelProbe.class.getSimpleName();
  public static final String TITLE = "Achieved level for results with rubric criterion levels";
}
