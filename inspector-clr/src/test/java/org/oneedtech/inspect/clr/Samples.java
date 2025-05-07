package org.oneedtech.inspect.clr;

import org.oneedtech.inspect.test.Sample;

public class Samples {
	public static final class CLR20 {
		public static final class JSON {
			public final static Sample SIMPLE_JSON = new Sample("clr20/simple.json", true);
			public final static Sample SIMPLE_V1_JSON = new Sample("clr20/simple_v1.json", true);
			public final static Sample SIMPLE_JSON_NOPROOF = new Sample("clr20/simple-noproof.json", true);
			public final static Sample SIMPLE_JWT = new Sample("clr20/simple.jwt", true);
			public final static Sample COMPLEX_JSON = new Sample("clr20/complex.json", true);
		}
	}
}
