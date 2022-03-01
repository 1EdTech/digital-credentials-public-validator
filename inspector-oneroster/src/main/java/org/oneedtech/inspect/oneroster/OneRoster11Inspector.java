package org.oneedtech.inspect.oneroster;

import static org.oneedtech.inspect.util.net.HttpMethod.GET;

import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.oneedtech.inspect.core.MappedJsonInspector;
import org.oneedtech.inspect.core.schema.TransactionKey;
import org.oneedtech.inspect.schema.SchemaKeys;
import org.oneedtech.inspect.util.resource.ResourceType;

import com.google.common.collect.ImmutableSet;

/**
 * An Inspector for OneRoster 1.1.
 * 
 * @author mgylling
 */

/*
 * TODO - what would make the building of this faster? - Autogen of mapping
 * between endpoint/responseCode and schemas 
 * TODO - what would make maintenance
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
			//TODO autogen matter: 
			.add(TransactionKeys.GET_ALL_ACADEMIC_SESSIONS_200, SchemaKeys.OR_11_GETALLACADEMICSESSIONS_11_JSON)
			.add(TransactionKeys.GET_ALL_CLASSES_200, SchemaKeys.OR_11_GETALLCLASSES_11_JSON)
			.add(TransactionKeys.GET_ALL_COURSES_200, SchemaKeys.OR_11_GETALLCOURSES_11_JSON)
			.add(TransactionKeys.GET_ALL_DEMOGRAPHICS_200, SchemaKeys.OR_11_GETALLDEMOGRAPHICS_11_JSON)
			.add(TransactionKeys.GET_ALL_ENROLLMENTS_200, SchemaKeys.OR_11_GETALLENROLLMENTS_11_JSON)
			.add(TransactionKeys.GET_ALL_ORGS_200, SchemaKeys.OR_11_GETALLORGS_11_JSON)
			.add(TransactionKeys.GET_ALL_USERS_200, SchemaKeys.OR_11_GETALLUSERS_11_JSON);
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
		//TODO autogen matter: 
		public static final TransactionKey GET_ALL_ACADEMIC_SESSIONS_200 = new TransactionKey("getAllAcademicSessions", GET, "/academicSessions", OK);
		public static final TransactionKey GET_ALL_CLASSES_200 = new TransactionKey("getAllClasses", GET, "/classes", OK);
		public static final TransactionKey GET_ALL_COURSES_200 = new TransactionKey("getAllCourses", GET, "/courses", OK);
		public static final TransactionKey GET_ALL_DEMOGRAPHICS_200 = new TransactionKey("getAllDemographics", GET, "/demographics", OK);
		public static final TransactionKey GET_ALL_ENROLLMENTS_200 = new TransactionKey("getAllEnrollments", GET, "/enrollments", OK);
		public static final TransactionKey GET_ALL_ORGS_200 = new TransactionKey("getAllOrgs", GET, "/orgs", OK);
		public static final TransactionKey GET_ALL_USERS_200 = new TransactionKey("getAllUsers", GET, "/users", OK);

		
	}

	// private static final Logger logger = LogManager.getLogger();

}
