package org.oneedtech.inspect.vc.probe.validation;

import java.util.List;
import java.util.stream.Collectors;

import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.TextNode;

public class ValidationRdfTypePropertyProbe extends ValidationPropertyProbe {
    public ValidationRdfTypePropertyProbe(Validation validation) {
        super(validation);
    }

    public ValidationRdfTypePropertyProbe(Validation validation, boolean fullValidate) {
        super(validation, fullValidate);
    }

    @Override
    protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
        if (!validation.isRequired()) {
            // check if we have a default type
            if (validation.getDefaultType() != null) {
                JsonNodeFactory factory = JsonNodeFactory.instance;
                TextNode textNode = factory.textNode(validation.getDefaultType());
                // validate with default value
                return validate(textNode, ctx);
            }
        }

        return error("Required property " + validation.getName() + " not present in " + node.toPrettyString(), ctx);
    }

    @Override
    protected ReportItems validate(JsonNode node, RunContext ctx) {
        ReportItems result = super.validate(node, ctx);
        if (result.contains(Outcome.ERROR, Outcome.FATAL)) {
            return result;
        }
        if (!validation.getMustContainOne().isEmpty()) {
            List<String> values = JsonNodeUtil.asStringList(node);
            boolean valid = validation.getMustContainOne().stream().anyMatch(type -> values.contains(type));
            if (!valid) {
                return new ReportItems(List.of(result,
                    fatal("Node " + validation.getName() + " of type " + node.asText()
                        + " does not have type among allowed values (" + validation.getMustContainOne().stream().collect(Collectors.joining(",")) + ")", ctx)
                ));
            }
        }
        return new ReportItems(List.of(result, success(ctx)));
    }
}
