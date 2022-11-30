package org.oneedtech.inspect.vc.probe.validation;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.Validation.MessageLevel;

import com.fasterxml.jackson.databind.JsonNode;

public class ValidationIssuerPropertyProbe extends ValidationPropertyProbe {

    public ValidationIssuerPropertyProbe(Validation validation) {
        super(validation);
    }

    public ValidationIssuerPropertyProbe(Validation validation, boolean fullValidate) {
        super(validation, fullValidate);
    }

    @Override
    protected ReportItems validate(JsonNode node, RunContext ctx) {
        if (!node.asText().matches("^http(s)?://")) {
            return buildResponse("Issuer Profile " + node.toString() + " not hosted with HTTP-based identifier."  +
                "Many platforms can only handle HTTP(s)-hosted issuers.", ctx);
        }
        return success(ctx);
    }

    private ReportItems buildResponse(String msg, RunContext ctx) {
        if (validation.getMessageLevel() == MessageLevel.Warning) {
            return warning(msg, ctx);
        }
        return error(msg, ctx);
    }
}
