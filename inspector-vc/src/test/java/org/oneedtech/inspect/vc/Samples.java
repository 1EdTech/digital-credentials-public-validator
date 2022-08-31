package org.oneedtech.inspect.vc;

import org.oneedtech.inspect.test.Sample;

public class Samples {
	public static final class OB30 {					
		public static final class SVG {			
			public final static Sample SIMPLE_JSON_SVG = new Sample("ob30/simple-json.svg", true);
			public final static Sample SIMPLE_JWT_SVG = new Sample("ob30/simple-jwt.svg", true);						
		}
		public static final class JSON {			
			public final static Sample COMPLETE_JSON = new Sample("ob30/complete.json", false);
			public final static Sample SIMPLE_JSON = new Sample("ob30/simple.json", true);
			public final static Sample SIMPLE_JSON_NOPROOF = new Sample("ob30/simple-noproof.json", false);
			public final static Sample SIMPLE_JSON_UNKNOWN_TYPE = new Sample("ob30/simple-err-type.json", false);
			public final static Sample SIMPLE_JSON_PROOF_ERROR = new Sample("ob30/simple-err-proof.json", false);			
			public final static Sample SIMPLE_JSON_EXPIRED = new Sample("ob30/simple-err-expired.json", false);
			public final static Sample SIMPLE_JSON_ISSUED = new Sample("ob30/simple-err-issued.json", false);
			public final static Sample SIMPLE_JSON_ISSUER = new Sample("ob30/simple-err-issuer.json", false);
			public final static Sample SIMPLE_JSON_ERR_CONTEXT = new Sample("ob30/simple-err-context.json", false);
		}
		public static final class PNG {			
			public final static Sample SIMPLE_JWT_PNG = new Sample("ob30/simple-jwt.png", true);
			public final static Sample SIMPLE_JSON_PNG = new Sample("ob30/simple-json.png", true);						
		}
		public static final class JWT {			
			public final static Sample SIMPLE_JWT = new Sample("ob30/simple.jwt", true);
		}
	}

	public static final class CLR20 {					
		public static final class JSON {			
			public final static Sample SIMPLE_JSON = new Sample("clr20/simple.json", true);
			public final static Sample SIMPLE_JSON_NOPROOF = new Sample("clr20/simple-noproof.json", true);
			public final static Sample SIMPLE_JWT = new Sample("clr20/simple.jwt", true);
		}
	}
}
