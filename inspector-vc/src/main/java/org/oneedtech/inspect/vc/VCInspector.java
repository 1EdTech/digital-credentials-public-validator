package org.oneedtech.inspect.vc;

import java.util.ArrayList;
import java.util.List;

import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;

/**
 * Abstract base for verifiable credentials inspectors/verifiers.
 * @author mgylling
 */
public abstract class VCInspector extends Inspector {
	
	protected <B extends VCInspector.Builder<?>> VCInspector(B builder) {
		super(builder);		
	}
	
	protected Report abort(RunContext ctx, List<ReportItems> accumulator, int probeCount) {
		return new Report(ctx, new ReportItems(accumulator), probeCount);
	}
	
	protected boolean broken(List<ReportItems> accumulator) {
		for(ReportItems items : accumulator) {
			if(items.contains(Outcome.FATAL, Outcome.EXCEPTION, Outcome.NOT_RUN)) return true;
		}
		return false;
	}
	
	public abstract static class Builder<B extends VCInspector.Builder<B>> extends Inspector.Builder<B> {
		final List<Probe<Credential>> probes; 

		public Builder() {
			super();
			this.probes = new ArrayList<>();
		}
				
		public VCInspector.Builder<B> add(Probe<Credential> probe) {
			probes.add(probe);
			return this;
		}
	}
}