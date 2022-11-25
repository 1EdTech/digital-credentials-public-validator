package org.oneedtech.inspect.vc.probe;

import java.util.List;
import java.util.function.BiFunction;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;

public class PropertyProbe extends Probe<JsonNode> {
    private final String propertyName;
    private BiFunction<List<String>, RunContext, ReportItems> validations;

    public PropertyProbe(String id, String propertyName) {
        super(id);
        this.propertyName = propertyName;
        this.validations = this::defaultValidation;
    }

    public void setValidations(BiFunction<List<String>, RunContext, ReportItems> validations) {
        this.validations = validations;
    }

    @Override
    public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
        JsonNode propertyNode = root.get(propertyName);
		if (propertyNode == null) {
			return reportForNonExistentProperty(ctx);
        }
		List<String> values = JsonNodeUtil.asStringList(propertyNode);
        return validations.apply(values, ctx);
    }
    protected ReportItems reportForNonExistentProperty(RunContext ctx) {
        return fatal("No " + propertyName + " property", ctx);
    }

    private ReportItems defaultValidation(List<String> nodeValues, RunContext ctx) {
        return notRun("Not additional validations run", ctx);
    }
}
