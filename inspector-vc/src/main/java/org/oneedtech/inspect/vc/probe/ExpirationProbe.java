package org.oneedtech.inspect.vc.probe;

import java.time.ZonedDateTime;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A Probe that verifies a credential's expiration status
 * @author mgylling
 */
public class ExpirationProbe extends Probe<Credential> {

	public ExpirationProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {
		/*
		 *  If the AchievementCredential or EndorsementCredential has an “expirationDate” or "validUntil" property
		 *	and the expiration date is prior to the current date, the credential has expired.
		 */
		JsonNode node = crd.getJson().get(crd.getExpiresAtPropertyName());
		if(node != null && !node.isNull()) {
			try {
				ZonedDateTime expirationDate = ZonedDateTime.parse(node.textValue());
				if (ZonedDateTime.now().isAfter(expirationDate)) {
					return fatal("The credential has expired (expiration date or validUntil was " + node.asText() + ").", ctx);
				}
			} catch (Exception e) {
				return exception("Error while checking expirationDate or validUntil: " + e.getMessage(), ctx.getResource());
			}
		}
		return success(ctx);
	}

	public static final String ID = ExpirationProbe.class.getSimpleName();
}
