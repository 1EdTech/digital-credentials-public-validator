package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.vc.Credential.Type.*;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.asStringList;

import java.util.List;
import java.util.function.Predicate;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Joiner;

//TODO refactor
public class Predicates {
	
	public static class OB30 {	
		public static class TypeProperty {			
			public static final Predicate<JsonNode> value = new Predicate<>() {						
				@Override
				public boolean test(JsonNode node) {
					List<String> values = asStringList(node);
					for(String exp : exp) {
						if(values.contains(exp)) return true;
					}			
					return false;
				}				
			};
			private static final List<String> exp = List.of(OpenBadgeCredential.name(), AchievementCredential.name(), VerifiablePresentation.name());
			public static final String msg = "The type property does not contain one of " + Joiner.on(", ").join(exp);
		}
	}
	
	public static class VC {	
		public static class TypeProperty {			
			public static final Predicate<JsonNode> value = new Predicate<>() {						
				@Override
				public boolean test(JsonNode node) {
					List<String> values = asStringList(node);			
					if(values.contains(exp)) return true;					
					return false;
				}				
			};
			private static final String exp = VerifiableCredential.name();
			public static final String msg = "The type property does not contain " + exp;
		}
	}
	
	
		
	
}

