package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;
import java.util.stream.Collectors;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential.CredentialEnum;

/**
 * A Probe that verifies a credential's type property.
 *
 * @author mgylling
 */
public class TypePropertyProbe extends PropertyProbe {
	private final CredentialEnum expected;

	public TypePropertyProbe(CredentialEnum expected) {
		super(ID, "type");
		this.expected = checkNotNull(expected);
		this.setValidations(this::validate);
	}

	public ReportItems validate(List<String> values, RunContext ctx) {
		List<String> requiredTypeValues = expected.getRequiredTypeValues();
		if (!requiredTypeValues.isEmpty()) {
			if (!requiredTypeValues.stream().allMatch(requiredValue -> values.contains(requiredValue))) {
				return fatal(formatMessage(requiredTypeValues), ctx);
			}
		}

		List<String> allowedValues = expected.getAllowedTypeValues();
		if (allowedValues.isEmpty()) {
			// TODO implement
			throw new IllegalStateException();
		}
		if (!values.stream().anyMatch(v -> allowedValues.contains(v))) {
			return fatal(formatMessage(values), ctx);
		}

		return success(ctx);
	}

	private String formatMessage(List<String> values) {
		StringBuffer buffer = new StringBuffer("The type property does not contain ");
		if (values.size() > 1) {
			buffer.append("one of");
			buffer.append(values.stream()
				.map(value -> "'" + value + "'")
				.collect(Collectors.joining(" or "))
			);

		} else {
			buffer.append("the entry '" + values.get(0) + "'");
		}
		return buffer.toString();
	}

	public static final String ID = TypePropertyProbe.class.getSimpleName();
}
