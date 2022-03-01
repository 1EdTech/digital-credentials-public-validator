package org.oneedtech.inspect.oneroster;

import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.*;

import org.oneedtech.inspect.test.Sample;

public class Samples {

	public static final class OR11 {
		//valid
		public static final Sample AS678 = new Sample("or11/1574845678/academicSessions.json", true, GET_ALL_ACADEMIC_SESSIONS_200);  
		public static final Sample CL678 = new Sample("or11/1574845678/classes.json", true, GET_ALL_CLASSES_200);
		public static final Sample CO678 = new Sample("or11/1574845678/courses.json", true, GET_ALL_COURSES_200);		
		public static final Sample EN678 = new Sample("or11/1574845678/enrollments.json", true, GET_ALL_ENROLLMENTS_200);
		public static final Sample OR678 = new Sample("or11/1574845678/orgs.json", true, GET_ALL_ORGS_200);
		public static final Sample US678 = new Sample("or11/1574845678/users.json", true, GET_ALL_USERS_200);		
		public static final Sample AS198 = new Sample("or11/1598444198/academicSessions.json",true, GET_ALL_ACADEMIC_SESSIONS_200);
		public static final Sample CL198 = new Sample("or11/1598444198/classes.json", true, GET_ALL_CLASSES_200);
		public static final Sample CO198 = new Sample("or11/1598444198/courses.json", true, GET_ALL_COURSES_200);		
		public static final Sample OR198 = new Sample("or11/1598444198/orgs.json", true, GET_ALL_ORGS_200);
		public static final Sample US198 = new Sample("or11/1598444198/users.json", true, GET_ALL_USERS_200);
		
		//invalid
		public static final Sample AS678I = new Sample("or11/1574845678/academicSessions-invalid.json", false, GET_ALL_ACADEMIC_SESSIONS_200);
		//TODO which is correct, schema or sample? demographics "true" vs boolean
		public static final Sample D678I = new Sample("or11/1574845678/demographics.json", false, GET_ALL_DEMOGRAPHICS_200);
		public static final Sample D198 = new Sample("or11/1598444198/demographics.json", false, GET_ALL_DEMOGRAPHICS_200);

	}
}
