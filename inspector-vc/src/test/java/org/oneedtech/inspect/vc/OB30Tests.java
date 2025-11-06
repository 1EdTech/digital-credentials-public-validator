package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.oneedtech.inspect.test.Assertions.assertErrorCount;
import static org.oneedtech.inspect.test.Assertions.assertFatalCount;
import static org.oneedtech.inspect.test.Assertions.assertHasProbeID;
import static org.oneedtech.inspect.test.Assertions.assertInvalid;
import static org.oneedtech.inspect.test.Assertions.assertValid;
import static org.oneedtech.inspect.test.Assertions.assertWarning;
import static org.velocitynetwork.contracts.CryptoUtils.hexToBytes;

import com.google.common.collect.Iterables;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDValidationProbe;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialSubjectProbe;
import org.oneedtech.inspect.vc.probe.EmbeddedProofModel;
import org.oneedtech.inspect.vc.probe.EmbeddedProofProbe;
import org.oneedtech.inspect.vc.probe.EvidenceProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.IssuerProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.status.bitstring.BitstringStatusListProbe;
import org.velocitynetwork.contracts.VelocityNetworkDidResolver;
import org.velocitynetwork.contracts.VelocityNetworkMetadataRegistry;
import org.velocitynetwork.contracts.VelocityNetworkMetadataRegistryFacade;

public class OB30Tests {
  private static OB30Inspector validator;
  private static boolean verbose = true;

  @BeforeAll
  static void setup() {
    validator =
        new OB30Inspector.Builder()
            .set(Behavior.TEST_INCLUDE_SUCCESS, true)
            .set(Behavior.VALIDATOR_FAIL_FAST, true)
            .inject(
                Inspector.InjectionKeys.DID_RESOLUTION_SERVICE_URL,
                "http://dev.uniresolver.io/1.0/identifiers/")
            .inject(
                VCInspector.InjectionKeys.VNF_CONFIG,
                Map.of(
                    VCInspector.InjectionKeys.VNF_REGISTRY,
                        new MockVelocityNetworkMetadataRegistry()))
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
	void testSimple1ObValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_1OB.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleV1JsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_V1_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertWarning(report);
		});
	}

	@Test
	void testSimpleDidKeyMethodJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_DID_KEY_METHOD_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	@Disabled
	void testSimpleDidWebMethodJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_DID_WEB_METHOD_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleMultipleProofsJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_MULTIPLE_PROOF_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			// the only error is due to the lack of JSON-LD context for "SomeProofType"
			assertErrorCount(report, 1);
			assertHasProbeID(report, JsonLDValidationProbe.ID, true);
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
  void testVelocityJWTValid() {
    assertDoesNotThrow(
        () -> {
          Report report = validator.run(Samples.OB30.JWT.VELOCITY_JWT.asFileResource());
          if (verbose) PrintHelper.print(report, true);
		  assertInvalid(report); // due to the lack of ob's extension context
        //   assertWarning(report); // due to the use of VC DM v1.1 context
        });
  }

  @Test
	void testSimpleV1PNGJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.PNG.SIMPLE_V1_JWT_PNG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			// TODO: moved to warning due to:
			// - json schema validation error against canonical schema (json-ld schema validates)
			// - outdated context version
			// assertValid(report);
			assertWarning(report);
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
	void testSimpleV1JsonSVGJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.SVG.SIMPLE_V1_JWT_SVG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			// - json schema validation error against canonical schema (json-ld schema validates)
			// - outdated context version
			assertWarning(report);
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
    assertDoesNotThrow(
        () -> {
          Report report =
              validator.run(Samples.OB30.JSON.SIMPLE_JSON_PROOF_METHOD_ERROR.asFileResource());
          if (verbose) PrintHelper.print(report, true);
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
			Optional<GeneratedObject> proofModel = report.getGeneratedObject(EmbeddedProofModel.ID);
			assertTrue(proofModel.isPresent());
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
	void testSimpleJsonContextAlias() {
		//removed one of the reqd context uris
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_ALIAS_CONTEXT.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleJsonContextVersion() {
		//removed one of the reqd context uris
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_VERSION_CONTEXT.asFileResource());
			if(verbose) PrintHelper.print(report, true);
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
		//404 inline schema ref
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.COMPLETE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertFalse(report.asBoolean());
			assertTrue(Iterables.size(report.getErrors()) > 0);
			// assertTrue(Iterables.size(report.getExceptions()) > 0);
			assertHasProbeID(report, InlineJsonSchemaProbe.ID, true);
		});
	}

	@Test
	void testCompleteV1JsonInvalidInlineSchemaRef() throws Exception {
		//404 inline schema ref
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.COMPLETE_V1_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertFalse(report.asBoolean());
			assertTrue(Iterables.size(report.getErrors()) > 0);
			// assertTrue(Iterables.size(report.getExceptions()) > 0);
			assertHasProbeID(report, InlineJsonSchemaProbe.ID, true);
		});
	}

	@Test
	void testCredentialStatusRevoked() {
		// the credential is valid, but credentialStatus reveals it is revoked
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.CREDENTIAL_STATUS_REVOKED.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 0);
			assertFatalCount(report, 1);
			assertHasProbeID(report, RevocationListProbe.ID, true);
		});
	}

	@Test
	void testEddsa2022Warning() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_EDDSA_20222_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertWarning(report);
		});

	}

	@Test
	void testBitstringStatusListRevoked() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.BSL.CREDENTIAL_STATUS_REVOKED.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 0);
			assertFatalCount(report, 1);
			assertHasProbeID(report, BitstringStatusListProbe.ID, true);
		});

	}

	@Test
	void testRevokedWithBlankNodes() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.BSL.CREDENTIAL_STATUS_REVOKED_WITH_BLANK_NODES.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertInvalid(report);
			assertErrorCount(report, 0);
			assertFatalCount(report, 1);
			assertHasProbeID(report, BitstringStatusListProbe.ID, true);
		});

	}

	@Test
	void testDerivedCredentialValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.SD.DERIVED_CREDENTIAL.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

  static class MockVelocityNetworkMetadataRegistry
      implements VelocityNetworkMetadataRegistryFacade {
    public List<VelocityNetworkMetadataRegistry.CredentialMetadata> getPaidEntries(
        List<VelocityNetworkMetadataRegistry.CredentialIdentifier> _entryIndexes,
        String traceId,
        String caoDid,
        String burnerDid)
        throws Exception {
      return Arrays.asList(
          new VelocityNetworkMetadataRegistry.CredentialMetadata(
              new org.web3j.abi.datatypes.generated.Bytes2(
                  hexToBytes(VelocityNetworkDidResolver.PublicKeyResolver.VERSION)),
              new org.web3j.abi.datatypes.generated.Bytes2(hexToBytes("2936")),
              new org.web3j.abi.datatypes.generated.Bytes2(
                  hexToBytes(VelocityNetworkDidResolver.PublicKeyResolver.ALG_TYPE)),
              new org.web3j.abi.datatypes.DynamicBytes(
                  hexToBytes(
                      "d612d970fec0c4913bd7716d1c789a833ad0d1e5f0997db5246a0c2c76ca7f723002a5a801e4ebac44e6d2563b3bdfd3206e681a2fd4dfaeca59a1ebedeac5157ea40bef32485643d8e976348ac1fe718ceda037fb62174083af52e596b30d3d8fc672662594b79a0e95f0dd37b099ef57ba9e21ed5877d36ec97296c8cc839634dad283fd908fc2e599b19a57cc6b47a2efde255df6e24396f6563bed57c143d38af14ce6f342b6f307afe0259bb7bb95968a172613b5bba186603d39f71686df036b9edfcce3d532c1df393c73f7570ecc34a199fcedb62490a0237891ce375a7363dcee006a7cc75a7992f73c91e630a0d185576a20ed9f4975fa6d04625ca67c242333e0bc1335e9fe3d26700765bcdd851027b64c19c32a26a90e6b8e1c01bdd00aa28ba20a4b387a20c147d64fe3cf5ccd730c7828a2f5533ed2395a10f61e7816fcd817c01e78c6da13d58741d811d041862c962954309c7cfb22ce7ef01c412a53d757ee092ec3ec")),
              new org.web3j.abi.datatypes.DynamicBytes(
                  hexToBytes(
                      "65794a30655841694f694a4b563151694c434a68624763694f694a46557a49314e6b73694c434a72615751694f694a6b61575136643256694f6e4a6c5a326c7a64484a686369557a51544d774d4441365a4470336433637559574e745a574e76636e417463474a6b5a584e7763336871616d74685933567565575670644842754c6d4e7662534e325979317a615764756157356e4c57746c65533078496e302e65794a325979493665794a705a434936496d5630614756795a5856744f6a4234526a557a4e5559795a6b4d774f546c434d4545774d544246526d55794e7a4e425a54633152475531596d4d314e3259794e5463305a53396e5a5854516f584a6c5a47567564476c686245316c6447466b5958526854476c7a64456c7a6333566c636c5a445032466b5a484a6c63334d394d4867334d6a45334e7a41784e6d5a6b4d6a55304e7a51774d3055355a6d557a4e444135597a4e475930526a515556464d44677a4d5745324a6d78706333524a5a4430784e4449304d6a41334e6a45314f44517a4d7a49694c434a306558426c496a7062496b4e795a57526c626e52705957784e5a5852685a47463059557870633352495a57466b5a5849695853776961584e7a64575679496a6f695a476c6b4f6e646c596a70795a576470633352795958496c4d30457a4d4441774f6d5136643364334c6d466a6257566a62334a774c5842695a47567a63484e34616d707259574e31626e6c6c615852776269356a623230694c434a7063334e315957356a5a555268644755694f6949794d4449314c5441334c544534564441324f6a41344f6a45334c6a55344e316f694c434a6a636d566b5a5735306157467355335669616d566a6443493665794a7361584e30535751694f6a45304d6a51794d4463324d5455344e444d7a4d69776959574e6a6233567564456c6b496a6f694d4867334d6a45334e7a41784e6d5a6b4d6a55304e7a51774d3055355a6d557a4e444135597a4e475930526a515556464d44677a4d574532496e31394c434a7063334d694f694a6b61575136643256694f6e4a6c5a326c7a64484a686369557a51544d774d4441365a4470336433637559574e745a574e76636e417463474a6b5a584e7763336871616d74685933567565575670644842754c6d4e7662534973496d703061534936496d5630614756795a5856744f6a4234526a557a4e5559795a6b4d774f546c434d4545774d544246526d55794e7a4e425a54633152475531596d4d314e3259794e5463305a53396e5a5854516f584a6c5a47567564476c686245316c6447466b5958526854476c7a64456c7a6333566c636c5a445032466b5a484a6c63334d394d4867334d6a45334e7a41784e6d5a6b4d6a55304e7a51774d3055355a6d557a4e444135597a4e475930526a515556464d44677a4d5745324a6d78706333524a5a4430784e4449304d6a41334e6a45314f44517a4d7a49694c434a70595851694f6a45334e5449344d5467344f546373496d35695a6949364d5463314d6a67784f4467354e33302e6f7a36652d68374437376c7538666f567347546744744c456247645f66454558594d394651686c4b4b4f38764a593550614e376664336f737278487666346a5451654f4b734c4d582d633467446e4c625a354f703841"))));
		}
	}
}
