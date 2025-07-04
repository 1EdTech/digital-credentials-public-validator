package org.oneedtech.inspect.vc.probe;

import java.util.HashMap;
import java.util.Map;
import org.oneedtech.inspect.core.probe.GeneratedObject;

public class EmbeddedProofModel extends GeneratedObject {
  public static final String ID = "vc.embedded.proof";

  private final Map<String, String> intermediateValues;

  public EmbeddedProofModel() {
    super(ID, Type.EXTERNAL);
    this.intermediateValues = new HashMap<>();
  }

  public Map<String, String> getIntermediateValues() {
    return intermediateValues;
  }

  public void addIntermediateValue(String key, String value) {
    intermediateValues.put(key, value);
  }
}
