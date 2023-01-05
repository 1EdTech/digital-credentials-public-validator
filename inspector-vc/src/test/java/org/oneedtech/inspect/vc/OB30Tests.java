package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.*;
import static org.oneedtech.inspect.test.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialSubjectProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.IssuerProbe;
import org.oneedtech.inspect.vc.probe.EmbeddedProofProbe;
import org.oneedtech.inspect.vc.probe.EvidenceProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;

import com.google.common.collect.Iterables;

public class OB30Tests {
	private static OB30Inspector validator;
	private static boolean verbose = true;

	@BeforeAll
	static void setup() {
		validator = new OB30Inspector.Builder()
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)
				.set(Behavior.VALIDATOR_FAIL_FAST, true)
				.build();
	}

	@Test
	void testSimpleJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleDidMethodJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_DID_METHOD_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimplePNGPlainValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.PNG.SIMPLE_JSON_PNG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimplePNGJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.PNG.SIMPLE_JWT_PNG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleJsonSVGPlainValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.SVG.SIMPLE_JSON_SVG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleJsonSVGJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.SVG.SIMPLE_JWT_SVG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleJsonInvalidUnknownType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertFatalCount(report, 1);
			assertHasProbeID(report, TypePropertyProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidProofMethod() {
		// add some garbage chars to the verification method fragment
		// it will be treated a URL to a verification key, but the URL will not be found
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_PROOF_METHOD_ERROR.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 1);
			assertHasProbeID(report, EmbeddedProofProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidProofMethodNoScheme() {
		// The verificationMethod is not a URI (no scheme)
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_PROOF_METHOD_NO_SCHEME_ERROR.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 1);
			assertHasProbeID(report, EmbeddedProofProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidProofMethodUnknownScheme() {
		// The verificationMethod is not a URI (no scheme)
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_PROOF_METHOD_UNKNOWN_SCHEME_ERROR.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 1);
			assertHasProbeID(report, EmbeddedProofProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidProofMethodUnknownDidMethod() {
		// The verificationMethod is an unknown DID Method
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_PROOF_METHOD_UNKNOWN_DID_METHOD_ERROR.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 1);
			assertHasProbeID(report, EmbeddedProofProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidProofValue() {
		//add some garbage chars to proofValue
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_PROOF_VALUE_ERROR.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 1);
			assertHasProbeID(report, EmbeddedProofProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonExpired() {
		//"expirationDate": "2020-01-20T00:00:00Z",
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_EXPIRED.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertHasProbeID(report, ExpirationProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonContextError() {
		//removed one of the reqd context uris
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_ERR_CONTEXT.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertHasProbeID(report, ContextPropertyProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonSchemaError() throws Exception {
		//issuer removed
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_ISSUER.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertHasProbeID(report, JsonSchemaProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidCredentialSubjectType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_CREDENTIAL_SUBJECT_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, CredentialSubjectProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidCredentialSubjectIdentifierType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_CREDENTIAL_SUBJECT_IDENTIFIER_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, CredentialSubjectProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidCredentialSubjectResultType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_CREDENTIAL_SUBJECT_RESULT_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, CredentialSubjectProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidCredentialSubjectAchievementResultDescriptionType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_CREDENTIAL_SUBJECT_ACHIEVEMENT_RESULT_DESCRIPTION_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, CredentialSubjectProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidCredentialSubjectProfileType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_CREDENTIAL_SUBJECT_PROFILE_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, CredentialSubjectProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidEvidenceType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_EVIDENCE_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, EvidenceProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidIssuerType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_ISSUER_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, IssuerProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidIssuerParentOrgType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_ISSUER_PARENTORG_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, IssuerProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidIssuerOtherIdentifierType() {
		//add a dumb value to .type and remove the ob type
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_ISSUER_OTHERIDENTIFIER_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			// assertFatalCount(report, 1);
			assertHasProbeID(report, IssuerProbe.ID, true);
		});
	}

	@Disabled //TODO IssuanceVerifierProbe is not run because FATAL: InvalidSignature terminates
	@Test
	void testSimpleJsonNotIssued() {
		//"issuanceDate": "2040-01-01T00:00:00Z",
		//this breaks the proof too
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_ISSUED.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertHasProbeID(report, IssuanceProbe.ID, true);
		});
	}

	@Test
	void testCompleteJsonInvalidInlineSchemaRef() throws Exception {
		//404 inline schema ref, and 404 refresh uri
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.COMPLETE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertFalse(report.asBoolean());
			assertTrue(Iterables.size(report.getErrors()) > 0);
			assertTrue(Iterables.size(report.getExceptions()) > 0);
			assertHasProbeID(report, InlineJsonSchemaProbe.ID, true);
		});
	}

}
