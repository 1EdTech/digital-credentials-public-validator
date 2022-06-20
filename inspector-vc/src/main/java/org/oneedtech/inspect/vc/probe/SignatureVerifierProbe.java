package org.oneedtech.inspect.vc.probe;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

/**
 * A Probe that verifies credential signatures 
 * @author mlyon
 */
public class SignatureVerifierProbe extends Probe<Credential> {
	
	public SignatureVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {

		//TODO @Miles -- if sigs fail, report OutCome.Fatal
					
		return success(ctx);
	}
	
	public static final String ID = SignatureVerifierProbe.class.getSimpleName();

}