package org.oneedtech.inspect.vc.verification;

import java.net.URI;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;

public class Eddsa2022DataIntegrity extends DataIntegrityProof {
	public static final URI[] DEFAULT_JSONLD_CONTEXTS = { DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_DATAINTEGRITY_V1 };
	public static final DocumentLoader DEFAULT_DOCUMENT_LOADER = DataIntegrityContexts.DOCUMENT_LOADER;

	public static Builder<? extends Builder<?>> builder() {
		return new Builder(new Eddsa2022DataIntegrity());
	}

	/*
	 * Factory methods
	 */

	public static class Builder<B extends Builder<B>> extends DataIntegrityProof.Builder<B> {

		private boolean addCryptosuite = true;

		public Builder(DataIntegrityProof jsonLdObject) {
			super(jsonLdObject);
		}

		@Override
		public B base(JsonLDObject base) {
			addCryptosuite = false;
			return super.base(base);
		}

		@Override
		public DataIntegrityProof build() {
			super.build();

			if (addCryptosuite) {
				JsonLDUtils.jsonLdAdd(this.jsonLdObject, "cryptosuite", "eddsa-rdfc-2022");
			}

			return (DataIntegrityProof) this.jsonLdObject;

		}
	}
}