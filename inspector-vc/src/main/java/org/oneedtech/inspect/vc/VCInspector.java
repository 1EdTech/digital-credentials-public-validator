package org.oneedtech.inspect.vc;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.fasterxml.jackson.databind.JsonNode;

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
		return broken(accumulator, false);
	}

	protected boolean broken(List<ReportItems> accumulator, boolean force) {
		if(!force && getBehavior(Inspector.Behavior.VALIDATOR_FAIL_FAST) == Boolean.FALSE) {
			return false;
		}
		for(ReportItems items : accumulator) {
			if(items.contains(Outcome.FATAL, Outcome.EXCEPTION)) return true;
		}
		return false;
	}

	/**
	 * If the AchievementCredential or EndorsementCredential has a “refreshService” property and the type of the
	 * RefreshService object is “1EdTechCredentialRefresh”, you should fetch the refreshed credential from the URL
	 * provided, then start the verification process over using the response as input. If the request fails,
	 * the credential is invalid.
	 */
	protected Optional<String> checkRefreshService(VerifiableCredential crd, RunContext ctx) {
		JsonNode refreshServiceNode = crd.getJson().get("refreshService");
		if(refreshServiceNode != null) {
			JsonNode serviceTypeNode = refreshServiceNode.get("type");
			if(serviceTypeNode != null && serviceTypeNode.asText().equals("1EdTechCredentialRefresh")) {
				JsonNode serviceURINode = refreshServiceNode.get("id");
				if(serviceURINode != null) {
					return Optional.of(serviceURINode.asText());
				}
			}
		}
		return Optional.empty();
	}

	/**
	 * Creates a caching document loader for loading json resources
	 * @return document loader for loading json resources
	 */
	protected DocumentLoader getDocumentLoader() {
		return new CachingDocumentLoader();
	}

    protected static final String REFRESHED = "is.refreshed.credential";

	public abstract static class Builder<B extends VCInspector.Builder<B>> extends Inspector.Builder<B> {
		final List<Probe<VerifiableCredential>> probes;

		public Builder() {
			super();
			this.probes = new ArrayList<>();
		}

		public VCInspector.Builder<B> add(Probe<VerifiableCredential> probe) {
			probes.add(probe);
			return this;
		}
	}
}