package org.oneedtech.inspect.vc;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;
import org.oneedtech.inspect.vc.util.PrimitiveValueValidator;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * A wrapper object for a OB 2.0 assertion. This contains e.g. the origin resource
 * and the extracted JSON data plus any other stuff Probes need.
 * @author xaracil
 */
public class Assertion extends Credential {

	final Assertion.Type assertionType;

    protected Assertion(Resource resource, JsonNode data, String jwt, Map<CredentialEnum, SchemaKey> schemas) {
        super(resource.getID(), resource, data, jwt, schemas);

        JsonNode typeNode = jsonData.get("type");
        this.assertionType = Assertion.Type.valueOf(typeNode);
    }

    @Override
    public CredentialEnum getCredentialType() {
        return assertionType;
    }

    @Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("super", super.toString())
				.add("assertionType", assertionType)
				.toString();
	}

    public List<Validation> getValidations() {
        return validationMap.get(assertionType);
    }

	private static final Map<CredentialEnum, SchemaKey> schemas = new ImmutableMap.Builder<CredentialEnum, SchemaKey>()
			.put(Type.Assertion, Catalog.OB_21_ASSERTION_JSON)
			.build();

    public static class Builder extends Credential.Builder<Assertion> {

        @Override
        public Assertion build() {
            // transform key of schemas map to string because the type of the key in the base map is generic
            // and our specific key is an Enum
            return new Assertion(getResource(), getJsonData(), getJwt(), schemas);
        }
    }

    public enum Type implements CredentialEnum {
		Assertion(List.of("Assertion")),
		BadgeClass(List.of("BadgeClass")),

        AlignmentObject(List.of("AlignmentObject")),
        Criteria(List.of("Criteria")),
        CryptographicKey(List.of("CryptographicKey")),
        Endorsement(List.of("Endorsement")),
        EndorsementClaim(List.of("EndorsementClaim")),
        Evidence(List.of("Evidence")),
        ExpectedRecipientProfile(List.of("ExpectedRecipientProfile")),
        Extension(List.of("Extension")),
        IdentityObject(List.of("IdentityObject")),
        Image(List.of("Image")),
        Issuer(List.of("Issuer")),
        Profile(List.of("Profile")),
        RevocationList(List.of("RevocationList")),
        VerificationObject(List.of("VerificationObject")),
        VerificationObjectAssertion(List.of("VerificationObjectAssertion")),
        VerificationObjectIssuer(List.of("VerificationObjectIssuer")),
        Unknown(Collections.emptyList());

        public static List<Type> primaryObjects = List.of(Assertion, BadgeClass, Issuer, Profile, Endorsement);

        private final List<String> allowedTypeValues;

        Type(List<String> typeValues) {
            this.allowedTypeValues = typeValues;
        }

		public static Assertion.Type valueOf (JsonNode typeNode) {
			if(typeNode != null) {
                List<String> values = JsonNodeUtil.asStringList(typeNode);
                for (String value : values) {
                    Type found = Arrays.stream(Type.values())
                        .filter(type -> value.equals(type.toString()))
                        .findFirst()
                        .orElse(Unknown);
                    if (found != Unknown) {
                        return found;
                    }
                }
			}
			return Unknown;
        }

        @Override
        public List<String> getRequiredTypeValues() {
            return Collections.emptyList();
        }

        @Override
        public List<String> getAllowedTypeValues() {
            return allowedTypeValues;
        }

        @Override
        public List<String> getContextUris() {
            return List.of("https://w3id.org/openbadges/v2") ;
        }

        public List<Validation> getValidations() {
            return validationMap.get(this);
        }
	}

    public enum ValueType {
        BOOLEAN(PrimitiveValueValidator::validateBoolean),
        COMPACT_IRI(PrimitiveValueValidator::validateCompactIri),
        DATA_URI(PrimitiveValueValidator::validateDataUri),
        DATA_URI_OR_URL(PrimitiveValueValidator::validateDataUriOrUrl),
        DATETIME(PrimitiveValueValidator::validateDatetime),
        EMAIL(PrimitiveValueValidator::validateEmail),
        ID(null),
        IDENTITY_HASH(PrimitiveValueValidator::validateIdentityHash),
        IRI(PrimitiveValueValidator::validateIri),
        LANGUAGE(PrimitiveValueValidator::validateLanguage),
        MARKDOWN_TEXT(PrimitiveValueValidator::validateMarkdown),
        RDF_TYPE(PrimitiveValueValidator::validateRdfType),
        TELEPHONE(PrimitiveValueValidator::validateTelephone),
        TEXT(PrimitiveValueValidator::validateText),
        TEXT_OR_NUMBER(PrimitiveValueValidator::validateTextOrNumber),
        URL(PrimitiveValueValidator::validateUrl),
        URL_AUTHORITY(PrimitiveValueValidator::validateUrlAuthority);

        private final Function<JsonNode, Boolean> validationFunction;

        private ValueType(Function<JsonNode, Boolean> validationFunction) {
            this.validationFunction = validationFunction;
        }

        public Function<JsonNode, Boolean> getValidationFunction() {
            return validationFunction;
        }

        public static List<ValueType> primitives = List.of(BOOLEAN, DATA_URI_OR_URL, DATETIME, ID, IDENTITY_HASH, IRI, LANGUAGE, MARKDOWN_TEXT,
        TELEPHONE, TEXT, TEXT_OR_NUMBER, URL, URL_AUTHORITY);
    }

    public static Map<Type, List<Validation>> validationMap = new ImmutableMap.Builder<Type, List<Validation>>()
    .put(Type.Assertion, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(true).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(true).mustContainOneType(List.of(Type.Assertion)).build(),
        new Validation.Builder().name("recipient").type(ValueType.ID).expectedType(Type.IdentityObject).required(true).build(),
        new Validation.Builder().name("badge").type(ValueType.ID).prerequisite("ASN_FLATTEN_BC").expectedType(Type.BadgeClass).fetch(true).required(true).build(),
        new Validation.Builder().name("verification").type(ValueType.ID).expectedType(Type.VerificationObjectAssertion).required(true).build(),
        new Validation.Builder().name("issuedOn").type(ValueType.DATETIME).required(true).build(),
        new Validation.Builder().name("expires").type(ValueType.DATETIME).required(false).build(),
        new Validation.Builder().name("image").type(ValueType.ID).required(false).allowRemoteUrl(true).expectedType(Type.Image).fetch(false).allowDataUri(false).build(),
        new Validation.Builder().name("narrative").type(ValueType.MARKDOWN_TEXT).required(false).build(),
        new Validation.Builder().name("evidence").type(ValueType.ID).allowRemoteUrl(true).expectedType(Type.Evidence).many(true).fetch(false).required(false).build()
    ))
    .put(Type.BadgeClass, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(true).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(true).mustContainOneType(List.of(Type.BadgeClass)).build(),
        new Validation.Builder().name("issuer").type(ValueType.ID).prerequisite("BC_FLATTEN_ISS").expectedType(Type.Profile).fetch(true).required(true).build(),
        new Validation.Builder().name("name").type(ValueType.TEXT).required(true).build(),
        new Validation.Builder().name("description").type(ValueType.TEXT).required(true).build(),
        new Validation.Builder().name("image").type(ValueType.ID).required(false).allowRemoteUrl(true).expectedType(Type.Image).fetch(false).allowDataUri(true).build(),
        new Validation.Builder().name("criteria").type(ValueType.ID).expectedType(Type.Criteria).fetch(false).required(true).allowRemoteUrl(true).build(),
        new Validation.Builder().name("alignment").type(ValueType.ID).expectedType(Type.AlignmentObject).many(true).fetch(false).required(false).build(),
        new Validation.Builder().name("tags").type(ValueType.TEXT).many(true).required(false).build()
    ))
    .put(Type.AlignmentObject, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).many(true).required(false).defaultType(Type.AlignmentObject).build(),
        new Validation.Builder().name("targetName").type(ValueType.TEXT).required(true).build(),
        new Validation.Builder().name("targetUrl").type(ValueType.URL).required(true).build(),
        new Validation.Builder().name("description").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("targetFramework").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("targetCode").type(ValueType.TEXT).required(false).build()
    ))
    .put(Type.Criteria, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).many(true).required(false).defaultType(Type.Criteria).build(),
        new Validation.Builder().name("id").type(ValueType.IRI).required(false).build(),
        new Validation.Builder().name("narrative").type(ValueType.MARKDOWN_TEXT).required(false).build()
    ))
    .put(Type.CryptographicKey, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(false).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(false).many(true).defaultType(Type.CryptographicKey).build(),
        new Validation.Builder().name("owner").type(ValueType.IRI).required(false).fetch(true).build(),
        new Validation.Builder().name("publicKeyPem").type(ValueType.TEXT).required(false).build()
    ))
    .put(Type.Endorsement, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(true).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(true).mustContainOneType(List.of(Type.Endorsement)).build(),
        new Validation.Builder().name("claim").type(ValueType.ID).required(true).allowRemoteUrl(false).fetch(false).allowDataUri(false).expectedTypes(List.of(Type.EndorsementClaim, Type.Endorsement)).fullValidate(false).build(),
        new Validation.Builder().name("issuedOn").type(ValueType.DATETIME).required(true).build(),
        new Validation.Builder().name("issuer").type(ValueType.ID).expectedType(Type.Profile).fetch(true).required(true).build(),
        new Validation.Builder().name("verification").build()
    ))
    .put(Type.EndorsementClaim, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(true).build(),
        new Validation.Builder().name("endorsementComment").type(ValueType.MARKDOWN_TEXT).required(false).build()
    ))
    .put(Type.Evidence, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).many(true).required(false).defaultType(Type.Evidence).build(),
        new Validation.Builder().name("id").type(ValueType.IRI).required(false).build(),
        new Validation.Builder().name("narrative").type(ValueType.MARKDOWN_TEXT).required(false).build(),
        new Validation.Builder().name("name").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("description").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("genre").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("audience").type(ValueType.TEXT).required(false).build()
    ))
    .put(Type.ExpectedRecipientProfile, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(false).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(false).many(true).mustContainOneType(List.of(Type.Issuer, Type.Profile)).defaultType(Type.Profile).build(),
        new Validation.Builder().name("name").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("description").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("image").type(ValueType.ID).required(false).expectedType(Type.Image).fetch(false).allowDataUri(true).build(),
        new Validation.Builder().name("url").type(ValueType.URL).required(false).many(true).build(),
        new Validation.Builder().name("email").type(ValueType.EMAIL).required(false).many(true).build(),
        new Validation.Builder().name("telephone").type(ValueType.TELEPHONE).required(false).many(true).build(),
        new Validation.Builder().name("publicKey").type(ValueType.ID).many(true).expectedType(Type.CryptographicKey).fetch(false).required(false).build(),
        new Validation.Builder().name("verification").type(ValueType.ID).expectedType(Type.VerificationObjectIssuer).fetch(false).required(false).build()
    ))
    .put(Type.Extension, List.of())
    .put(Type.IdentityObject, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(false).mustContainOne(List.of("id", "email", "url", "telephone")).build(),
        new Validation.Builder().name("identity").type(ValueType.IDENTITY_HASH).required(true).build(),
        new Validation.Builder().name("hashed").type(ValueType.BOOLEAN).required(true).build(),
        new Validation.Builder().name("salt").type(ValueType.TEXT).required(false).build()
    ))
    .put(Type.Image, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).many(true).required(false).defaultType("schema:ImageObject").build(),
        new Validation.Builder().name("id").type(ValueType.DATA_URI_OR_URL).required(true).build(),
        new Validation.Builder().name("caption").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("author").type(ValueType.IRI).required(false).build()
    ))
    .put(Type.Issuer, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(true).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(true).mustContainOneType(List.of(Type.Issuer, Type.Profile)).build(),
        new Validation.Builder().name("name").type(ValueType.TEXT).required(true).build(),
        new Validation.Builder().name("description").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("image").type(ValueType.ID).required(false).allowRemoteUrl(true).expectedType(Type.Image).fetch(false).allowDataUri(true).build(),
        new Validation.Builder().name("url").type(ValueType.URL).required(true).build(),
        new Validation.Builder().name("email").type(ValueType.EMAIL).required(true).build(),
        new Validation.Builder().name("telephone").type(ValueType.TELEPHONE).required(false).build(),
        new Validation.Builder().name("publicKey").type(ValueType.ID).expectedType(Type.CryptographicKey).fetch(true).required(false).build(),
        new Validation.Builder().name("verification").type(ValueType.ID).expectedType(Type.VerificationObjectIssuer).fetch(false).required(false).build()
    ))
    .put(Type.Profile, List.of(
        new Validation.Builder().name("id").type(ValueType.IRI).required(true).build(),
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(true).mustContainOneType(List.of(Type.Issuer, Type.Profile)).build(),
        new Validation.Builder().name("name").type(ValueType.TEXT).required(true).build(),
        new Validation.Builder().name("description").type(ValueType.TEXT).required(false).build(),
        new Validation.Builder().name("image").type(ValueType.ID).required(false).allowRemoteUrl(true).expectedType(Type.Image).fetch(false).allowDataUri(true).build(),
        new Validation.Builder().name("url").type(ValueType.URL).required(true).build(),
        new Validation.Builder().name("email").type(ValueType.EMAIL).required(true).build(),
        new Validation.Builder().name("telephone").type(ValueType.TELEPHONE).required(false).build(),
        new Validation.Builder().name("publicKey").type(ValueType.ID).expectedType(Type.CryptographicKey).fetch(true).required(false).build(),
        new Validation.Builder().name("verification").type(ValueType.ID).expectedType(Type.VerificationObjectIssuer).fetch(false).required(false).build()
    ))
    .put(Type.RevocationList, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(true).mustContainOneType(List.of(Type.RevocationList)).build(),
        new Validation.Builder().name("id").type(ValueType.IRI).required(false).build()
    ))
    .put(Type.VerificationObject, List.of())
    .put(Type.VerificationObjectAssertion, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(true).many(false).mustContainOne(List.of("HostedBadge", "SignedBadge")).build(),
        new Validation.Builder().name("creator").type(ValueType.ID).expectedType(Type.CryptographicKey).fetch(true).required(false).prerequisite("ASSERTION_VERIFICATION_DEPENDENCIES").build()
    ))
    .put(Type.VerificationObjectIssuer, List.of(
        new Validation.Builder().name("type").type(ValueType.RDF_TYPE).required(false).many(true).defaultType(Type.VerificationObject).build(),
        new Validation.Builder().name("verificationProperty").type(ValueType.COMPACT_IRI).required(false).build(),
        new Validation.Builder().name("startsWith").type(ValueType.URL).required(false).build(),
        new Validation.Builder().name("allowedOrigins").type(ValueType.URL_AUTHORITY).required(false).many(true).build()
    ))
    .build();

    public static final String ID = Assertion.class.getCanonicalName();
}
