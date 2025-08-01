package org.oneedtech.inspect.vc.probe.validation;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import org.oneedtech.inspect.vc.Assertion.ValueType;
import org.oneedtech.inspect.vc.Validation;

/**
 * Factory for ValidationPropertyProbes
 * @author xaracil
 */
public class ValidationPropertyProbeFactory {
    public static ValidationPropertyProbe of(String type, Validation validation) {
		return of(type, validation, true);
	}

	public static ValidationPropertyProbe of(String type, Validation validation, boolean fullValidate) {
		checkNotNull(validation.getType());
		if (validation.getType() == ValueType.RDF_TYPE) {
			return new ValidationRdfTypePropertyProbe(type, validation, fullValidate);
		}
		if (validation.getType() == ValueType.IMAGE) {
			return new ValidationImagePropertyProbe(type, validation);
		}
		if (validation.getType() == ValueType.ISSUER) {
			return new ValidationIssuerPropertyProbe(type, validation);
		}
		return new ValidationPropertyProbe(type, validation, fullValidate);
	}
}
