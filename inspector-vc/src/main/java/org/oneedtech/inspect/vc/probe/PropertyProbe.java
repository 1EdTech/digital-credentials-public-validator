package org.oneedtech.inspect.vc.probe;

import java.util.function.BiFunction;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;

import com.fasterxml.jackson.databind.JsonNode;

public class PropertyProbe extends Probe<JsonNode> {
    private final String propertyName;
    private BiFunction<JsonNode, RunContext, ReportItems> validations;

    public PropertyProbe(String id, String propertyName) {
        super(id);
        this.propertyName = propertyName;
        this.validations = this::defaultValidation;
    }

    public void setValidations(BiFunction<JsonNode, RunContext, ReportItems> validations) {
        this.validations = validations;
    }

    @Override
    public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
        JsonNode propertyNode = root.get(propertyName);
		if (propertyNode == null) {
			return reportForNonExistentProperty(root, ctx);
        }

        return validations.apply(propertyNode, ctx);
    }

    protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
        return fatal("No " + propertyName + " property", ctx);
    }

    private ReportItems defaultValidation(JsonNode node, RunContext ctx) {
        return success(ctx);
    }
}
