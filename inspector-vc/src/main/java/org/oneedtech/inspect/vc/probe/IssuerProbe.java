package org.oneedtech.inspect.vc.probe;

import java.net.URI;
import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;

public class IssuerProbe extends Probe<JsonNode> {
    public IssuerProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
        JsonNode issuer = root.get("issuer");
        if(issuer == null) return error("no issuer node found", ctx);

        // check that type contains "Profile"
        if (!JsonNodeUtil.asStringList(issuer.get("type")).contains("Profile")) {
            return error("issuer is not of type \"Profile\"", ctx);
        }

        // check url is accessible
        if (issuer.hasNonNull("url")) {
            try {
                UriResource urlResource = new UriResource(new URI(issuer.get("url").asText().strip()));
                if (!urlResource.exists()) {
                    return warning("url \"" + issuer.get("url").asText().strip() + "\" in issuer is not accessible", ctx);
                }
            } catch (Exception e) {
                return warning("url \"" + issuer.get("url").asText().strip() + "\" in issuer is not accessible", ctx);
            }
        }

        // check other identifier
        if (issuer.hasNonNull("otherIdentifier")) {
			List<JsonNode> otherIdentifiers = JsonNodeUtil.asNodeList(issuer.get("otherIdentifier"));
			for (JsonNode otherIdentifier : otherIdentifiers) {
				// check that type contains "IdentifierEntry"
				if (!JsonNodeUtil.asStringList(otherIdentifier.get("type")).contains("IdentifierEntry")) {
					return error("otherIdentifier in issuer is not of type \"IdentifierEntry\"", ctx);
				}
			}
        }

        // check parent issuer
        if (issuer.hasNonNull("parentOrg")) {
			JsonNode parentOrg = issuer.get("parentOrg");
            // check that type contains "Profile"
            if (!JsonNodeUtil.asStringList(parentOrg.get("type")).contains("Profile")) {
                return error("parentOrg in issuer is not of type \"Profile\"", ctx);
            }
        }

        return success(ctx);
    }

    public static final String ID = IssuerProbe.class.getSimpleName();

}
