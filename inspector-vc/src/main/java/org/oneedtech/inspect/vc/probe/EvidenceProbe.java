package org.oneedtech.inspect.vc.probe;

import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;

public class EvidenceProbe extends Probe<JsonNode> {
    public EvidenceProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {

        if (root.hasNonNull("evidence")) {
            /*
             * evidence is an array, so check type of each element
             */
            List<JsonNode> evidences = JsonNodeUtil.asNodeList(root.get("evidence"));
            for (JsonNode evidence : evidences) {
                // check that type contains "Evidence"
                if (!JsonNodeUtil.asStringList(evidence.get("type")).contains("Evidence")) {
                    return error("evidence is not of type \"Evidence\"", ctx);
                }
            }
        }

        return success(ctx);
    }

    public static final String ID = EvidenceProbe.class.getSimpleName();

}
