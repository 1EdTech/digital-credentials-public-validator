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
public class ExpirationVerifierProbe extends Probe<Credential> {
	
	public ExpirationVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {
		/*		
		 *  If the AchievementCredential or EndorsementCredential has an “expirationDate” property 
		 *	and the expiration date is prior to the current date, the credential has expired. 
		 */		
		System.err.println("ExpirationVerifierProbe");
		JsonNode node = crd.getJson().get("expirationDate");
		if(node != null) {
			try {
				ZonedDateTime expirationDate = ZonedDateTime.parse(node.textValue());
				if (ZonedDateTime.now().isAfter(expirationDate)) {
					return fatal("The credential has expired (expiration date was " + node.asText() + ").", ctx);
				}	
			} catch (Exception e) {
				return exception("Error while checking expirationDate: " + e.getMessage(), ctx.getResource()); 
			}
		}
		return success(ctx);
	}
		
	public static final String ID = ExpirationVerifierProbe.class.getSimpleName(); 
}
