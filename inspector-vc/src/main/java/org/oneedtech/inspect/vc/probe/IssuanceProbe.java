package org.oneedtech.inspect.vc.probe;

import java.time.ZonedDateTime;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A Probe that verifies a credential's issuance status
 * @author mgylling
 */
public class IssuanceProbe extends Probe<Credential> {

	public IssuanceProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {
		/*
		 * If the AchievementCredential or EndorsementCredential “issuanceDate” or "validFrom"
		 * property after the current date, the credential is not yet valid.
		 */
		JsonNode node = crd.getJson().get(crd.getIssuedOnPropertyName());
		if(node != null) {
			try {
				ZonedDateTime issuanceDate = ZonedDateTime.parse(node.textValue());
				if (issuanceDate.isAfter(ZonedDateTime.now())) {
					return fatal("The credential is not yet issued or valid (issuance date or validFrom is " + node.asText() + ").", ctx);
				}
			} catch (Exception e) {
				return exception("Error while checking issuanceDate or ValidFrom: " + e.getMessage(), ctx.getResource());
			}
		}
		return success(ctx);
	}

	public static final String ID = IssuanceProbe.class.getSimpleName();
}
