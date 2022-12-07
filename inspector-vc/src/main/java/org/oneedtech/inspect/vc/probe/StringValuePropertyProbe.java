package org.oneedtech.inspect.vc.probe;

import java.util.List;
import java.util.function.BiFunction;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;

public class StringValuePropertyProbe extends PropertyProbe {
    private BiFunction<List<String>, RunContext, ReportItems> valueValidations;

    public StringValuePropertyProbe(String id, String propertyName) {
        super(id, propertyName);
        this.valueValidations = this::defaultValidation;
        super.setValidations(this::nodeValidation);
    }

    public void setValueValidations(BiFunction<List<String>, RunContext, ReportItems> validations) {
        this.valueValidations = validations;
    }

    private ReportItems nodeValidation(JsonNode node, RunContext ctx) {
		List<String> values = JsonNodeUtil.asStringList(node);
        return valueValidations.apply(values, ctx);
}

    private ReportItems defaultValidation(List<String> nodeValues, RunContext ctx) {
        return success(ctx);
    }


}
