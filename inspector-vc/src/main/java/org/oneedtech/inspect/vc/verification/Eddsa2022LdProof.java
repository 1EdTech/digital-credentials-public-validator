package org.oneedtech.inspect.vc.verification;

import java.net.URI;

import com.apicatalog.jsonld.loader.DocumentLoader;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;

public class Eddsa2022LdProof extends LdProof {
	public static final URI[] DEFAULT_JSONLD_CONTEXTS = { LDSecurityContexts.JSONLD_CONTEXT_W3ID_SUITES_ED25519_2022_V1 };
	public static final DocumentLoader DEFAULT_DOCUMENT_LOADER = LDSecurityContexts.DOCUMENT_LOADER;

	public static Builder<? extends Builder<?>> builder() {
		return new Builder(new Eddsa2022LdProof());
	}

	/*
	 * Factory methods
	 */

	public static class Builder<B extends Builder<B>> extends LdProof.Builder<B> {

		private boolean addCryptosuite = true;

		public Builder(LdProof jsonLdObject) {
			super(jsonLdObject);
		}

		@Override
		public B base(JsonLDObject base) {
			addCryptosuite = false;
			return super.base(base);
		}

		@Override
		public LdProof build() {
			super.build();

			if (addCryptosuite) {
				JsonLDUtils.jsonLdAdd(this.jsonLdObject, "cryptosuite", "eddsa-rdfc-2022");
			}

			return (LdProof) this.jsonLdObject;

		}
	}
}