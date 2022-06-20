package org.oneedtech.inspect.vc.probe;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

/**
 * A Probe that verifies credential proofs 
 * @author mlyon
 */
public class ProofVerifierProbe extends Probe<Credential> {
	
	public ProofVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {

		//TODO @Miles -- if proofs fail, report OutCome.Fatal
								
		return success(ctx);
	}

	public static final String ID = ProofVerifierProbe.class.getSimpleName();
}
