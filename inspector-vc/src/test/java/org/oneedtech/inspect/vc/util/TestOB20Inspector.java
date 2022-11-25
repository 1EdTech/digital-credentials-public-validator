package org.oneedtech.inspect.vc.util;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.Assertion;
import org.oneedtech.inspect.vc.OB20Inspector;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;

/**
 * OpenBadges 2.0 Test inspector.
 * It's a subclass of main OB2.0 inspector, setting redirection of urls to local resources for testing
 */
public class TestOB20Inspector extends OB20Inspector {
    protected final Map<URI, String> localDomains;

    protected TestOB20Inspector(TestBuilder builder) {
        super(builder);
        if (getBehavior(OB20Inspector.Behavior.ALLOW_LOCAL_REDIRECTION) == Boolean.TRUE) {
            this.localDomains = builder.localDomains;
        } else {
            this.localDomains = Collections.emptyMap();
        }
    }

    @Override
    protected JsonLDCompactionProve getCompactionProbe(Assertion assertion) {
        return new JsonLDCompactionProve(assertion.getCredentialType().getContextUris().get(0), localDomains);
    }

	public static class TestBuilder extends OB20Inspector.Builder {
		final Map<URI, String> localDomains;

		public TestBuilder() {
			super();
			// don't allow local redirections by default
			super.behaviors.put(OB20Inspector.Behavior.ALLOW_LOCAL_REDIRECTION, true);
			this.localDomains = new HashMap<>();
		}

		public TestBuilder add(URI localDomain, String resourcePath) {
			localDomains.put(localDomain, resourcePath);
			return this;
		}

		@Override
		public TestOB20Inspector build() {
			set(Specification.OB20);
			set(ResourceType.OPENBADGE);
			return new TestOB20Inspector(this);
		}
	}
}
