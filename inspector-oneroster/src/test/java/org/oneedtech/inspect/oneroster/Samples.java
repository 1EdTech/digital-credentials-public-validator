package org.oneedtech.inspect.oneroster;

import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.ACADEMIC_SESSIONS_GET_200;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.CLASSES_GET_200;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.COURSES_GET_200;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.DEMOGRAPHICS_GET_200;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.ENROLLMENTS_GET_200;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.ORGS_GET_200;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.USERS_GET_200;

import org.oneedtech.inspect.test.Sample;

public class Samples {

	public static final class OR11 {
		//valid
		public static final Sample AS678 = new Sample("or11/1574845678/academicSessions.json", true, ACADEMIC_SESSIONS_GET_200);  
		public static final Sample CL678 = new Sample("or11/1574845678/classes.json", true, CLASSES_GET_200);
		public static final Sample CO678 = new Sample("or11/1574845678/courses.json", true, COURSES_GET_200);		
		public static final Sample EN678 = new Sample("or11/1574845678/enrollments.json", true, ENROLLMENTS_GET_200);
		public static final Sample OR678 = new Sample("or11/1574845678/orgs.json", true, ORGS_GET_200);
		public static final Sample US678 = new Sample("or11/1574845678/users.json", true, USERS_GET_200);		
		public static final Sample AS198 = new Sample("or11/1598444198/academicSessions.json",true, ACADEMIC_SESSIONS_GET_200);
		public static final Sample CL198 = new Sample("or11/1598444198/classes.json", true, CLASSES_GET_200);
		public static final Sample CO198 = new Sample("or11/1598444198/courses.json", true, COURSES_GET_200);		
		public static final Sample OR198 = new Sample("or11/1598444198/orgs.json", true, ORGS_GET_200);
		public static final Sample US198 = new Sample("or11/1598444198/users.json", true, USERS_GET_200);
		
		//invalid
		public static final Sample AS678I = new Sample("or11/1574845678/academicSessions-invalid.json", false, ACADEMIC_SESSIONS_GET_200);
		//TODO which is correct, schema or sample? demographics "true" vs boolean
		public static final Sample D678I = new Sample("or11/1574845678/demographics.json", false, DEMOGRAPHICS_GET_200);
		public static final Sample D198 = new Sample("or11/1598444198/demographics.json", false, DEMOGRAPHICS_GET_200);

	}
}
