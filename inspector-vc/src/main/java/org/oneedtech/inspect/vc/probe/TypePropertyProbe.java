package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;

/**
 * A Probe that verifies a credential's type property.
 *
 * @author mgylling
 */
public class TypePropertyProbe extends PropertyProbe {
	private final VerifiableCredential.Type expected;

	public TypePropertyProbe(VerifiableCredential.Type expected) {
		super(ID, "type");
		this.expected = checkNotNull(expected);
		this.setValidations(this::validate);
	}

	public ReportItems validate(List<String> values, RunContext ctx) {
		if (!values.contains("VerifiableCredential")) {
			return fatal("The type property does not contain the entry 'VerifiableCredential'", ctx);
		}

		if (expected == VerifiableCredential.Type.OpenBadgeCredential) {
			if (!values.contains("OpenBadgeCredential") && !values.contains("AchievementCredential")) {
				return fatal("The type property does not contain one of 'OpenBadgeCredential' or 'AchievementCredential'", ctx);
			}
		} else if (expected == VerifiableCredential.Type.ClrCredential) {
			if (!values.contains("ClrCredential")) {
				return fatal("The type property does not contain the entry 'ClrCredential'", ctx);
			}
		} else if (expected == VerifiableCredential.Type.EndorsementCredential) {
			if (!values.contains("EndorsementCredential")) {
				return fatal("The type property does not contain the entry 'EndorsementCredential'", ctx);
			}
		} else {
			// TODO implement
			throw new IllegalStateException();
		}

		return success(ctx);
	}

	public static final String ID = TypePropertyProbe.class.getSimpleName();
}
