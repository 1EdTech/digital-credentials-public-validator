package org.oneedtech.inspect.vc.probe;

import org.oneedtech.inspect.core.probe.ObjectGenerator;
import org.oneedtech.inspect.vc.verification.URDNA2015Canonicalizer;

public class EmbeddedProofModelGenerator implements ObjectGenerator {
    private final EmbeddedProofModel model;

    public EmbeddedProofModelGenerator(URDNA2015Canonicalizer canonicalizer) {
        this.model = new EmbeddedProofModel(canonicalizer);
    }

    public EmbeddedProofModel getGeneratedObject() {
        return model;
    }
}
