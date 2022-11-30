package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.Assertion.ValueType;

/**
 * Factory for ValidationPropertyProbes
 * @author xaracil
 */
public class ValidationPropertyProbeFactory {
    public static ValidationPropertyProbe of(Validation validation) {
		return of(validation, false);
	}

	public static ValidationPropertyProbe of(Validation validation, boolean fullValidate) {
			checkNotNull(validation.getType());
		if (validation.getType() == ValueType.RDF_TYPE) {
			return new ValidationRdfTypePropertyProbe(validation, fullValidate);
		}
		if (validation.getType() == ValueType.IMAGE) {
			return new ValidationImagePropertyProbe(validation);
		}
		return new ValidationPropertyProbe(validation, fullValidate);
	}
}
