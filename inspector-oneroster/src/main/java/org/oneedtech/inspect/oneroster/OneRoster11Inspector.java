package org.oneedtech.inspect.oneroster;

import static org.oneedtech.inspect.util.net.HttpMethod.GET;

import java.util.stream.IntStream;

import org.oneedtech.inspect.core.MappedJsonInspector;
import org.oneedtech.inspect.core.schema.TransactionKey;
import org.oneedtech.inspect.schema.SchemaKeys;
import org.oneedtech.inspect.util.resource.ResourceType;

/**
 * An Inspector for OneRoster 1.1.
 * 
 * @author mgylling
 */

/*
 * TODO - what would make the building of this faster? - Autogen of mapping
 * between endpoint/responseCode and schemas TODO - what would make maintenance
 * of this faster? - webhooks when schemas are updated
 */
public class OneRoster11Inspector extends MappedJsonInspector {

	protected OneRoster11Inspector(OneRoster11Inspector.Builder builder) {
		super(builder);
	}

	public static class Builder extends MappedJsonInspector.Builder<OneRoster11Inspector.Builder> {

		public Builder() {
			super();
			set(ResourceType.JSON) // ?refine needed?
			// add default tests			
			.add(TransactionKeys.ACADEMIC_SESSIONS_GET_200, SchemaKeys.OR_11_GETALLACADEMICSESSIONS_11_JSON)
			.add(TransactionKeys.CLASSES_GET_200, SchemaKeys.OR_11_GETALLCLASSES_11_JSON)
			.add(TransactionKeys.COURSES_GET_200, SchemaKeys.OR_11_GETALLCOURSES_11_JSON)
			.add(TransactionKeys.DEMOGRAPHICS_GET_200, SchemaKeys.OR_11_GETALLDEMOGRAPHICS_11_JSON)
			.add(TransactionKeys.ENROLLMENTS_GET_200, SchemaKeys.OR_11_GETALLENROLLMENTS_11_JSON)
			.add(TransactionKeys.ORGS_GET_200, SchemaKeys.OR_11_GETALLORGS_11_JSON)
			.add(TransactionKeys.USERS_GET_200, SchemaKeys.OR_11_GETALLUSERS_11_JSON);
		}

		@SuppressWarnings("unchecked")
		@Override
		public OneRoster11Inspector build() {
			return new OneRoster11Inspector(this);
		}
	}

	public static class TransactionKeys {
		private static final int[] OK = new int[] { 200 };
		@SuppressWarnings("unused")
		private static final int[] ERR = IntStream.range(400, 500).toArray();

		public static final TransactionKey ACADEMIC_SESSIONS_GET_200 = new TransactionKey(GET, "/academicSessions", OK);
		public static final TransactionKey CLASSES_GET_200 = new TransactionKey(GET, "/classes", OK);
		public static final TransactionKey COURSES_GET_200 = new TransactionKey(GET, "/courses", OK);
		public static final TransactionKey DEMOGRAPHICS_GET_200 = new TransactionKey(GET, "/demographics", OK);
		public static final TransactionKey ENROLLMENTS_GET_200 = new TransactionKey(GET, "/enrollments", OK);
		public static final TransactionKey ORGS_GET_200 = new TransactionKey(GET, "/orgs", OK);
		public static final TransactionKey USERS_GET_200 = new TransactionKey(GET, "/users", OK);

	}

	// private static final Logger logger = LogManager.getLogger();

}
