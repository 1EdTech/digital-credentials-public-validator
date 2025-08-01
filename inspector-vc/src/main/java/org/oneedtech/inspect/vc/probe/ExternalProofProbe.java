package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import java.math.BigInteger;
import java.net.URI;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Set;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.probe.did.DidResolution;
import org.oneedtech.inspect.vc.probe.did.DidResolver;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;

/**
 * A Probe that verifies credential external proof (jwt)
 * @author mlyon
 */
public class ExternalProofProbe extends Probe<VerifiableCredential> {

	public ExternalProofProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(VerifiableCredential crd, RunContext ctx) throws Exception {
		try {
			verifySignature(crd, ctx);
		} catch (Exception e) {
			return fatal("Error verifying jwt signature: " + e.getMessage() + (e.getCause() != null ? ". Reason: " + e.getCause().getMessage() : ""), ctx);
		}
		return success(ctx);
	}

	private void verifySignature(VerifiableCredential crd, RunContext ctx) throws Exception {
		checkTrue(crd.getJwt().isPresent(), "no jwt supplied");
		checkTrue(crd.getJwt().get().length() > 0, "no jwt supplied");

		DecodedJWT decodedJwt = null;
		String jwt = crd.getJwt().get();

		List<String> parts = Splitter.on('.').splitToList(jwt);
		if(parts.size() != 3) throw new IllegalArgumentException("invalid jwt");

		final Decoder decoder = Base64.getUrlDecoder();
		String joseHeader = new String(decoder.decode(parts.get(0)));

		ObjectMapper mapper = ((ObjectMapper)ctx.get(RunContext.Key.JACKSON_OBJECTMAPPER));
    	JsonNode headerObj = mapper.readTree(joseHeader);

		//MUST be "RS256 or "ES256"
		JsonNode alg = headerObj.get("alg");
		Set<String> allowedAlgs = Set.of("RS256", "ES256");
		if (alg == null || !allowedAlgs.contains(alg.textValue())) {
			throw new Exception("alg must be present and must be either 'RS256' or 'ES256'");
		}

		// decoded jwt will check timestamps, but shall we explicitly break these out?
		// JWT verifier throws and exception with the cause when claims are invalid. Adding that cause
		// to the probe result can avoid having to explicitly check the claims.

		//Option 1, fetch directly from header
		JsonNode jwk = headerObj.get("jwk");

		//Option 2, fetch from a hosting url
		JsonNode kid = headerObj.get("kid");

		if(jwk == null && kid == null) { throw new Exception("Key must present in either jwk or kid value."); }
		if(kid != null){
			//Load jwk JsonNode from url and do the rest the same below.
			//TODO Consider additional testing.
			String kidUrl = kid.textValue();
			String jwkResponse = fetchJwk(kidUrl, ctx);
			if(jwkResponse == null) { throw new Exception("Unable to retrieve jwk value from url specified in kid."); }

			jwk = mapper.readTree(jwkResponse);
		}

		String kty = jwk.get("kty").asText();

		Algorithm algorithm; // Either RSA or ECDSA

		if ("RSA".equalsIgnoreCase(kty)) {
			// RSA Public Key
			String modulusString = jwk.get("n").asText();
			String exponentString = jwk.get("e").asText();

			BigInteger modulus = new BigInteger(1, decoder.decode(modulusString));
			BigInteger exponent = new BigInteger(1, decoder.decode(exponentString));

			RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory factory = KeyFactory.getInstance("RSA");
			RSAPublicKey pub = (RSAPublicKey) factory.generatePublic(pubSpec);

			algorithm = Algorithm.RSA256(pub, null);

		} else if ("EC".equalsIgnoreCase(kty)) {
			// ECDSA Public Key
			String xString = jwk.get("x").asText();
			String yString = jwk.get("y").asText();
			String crv = jwk.get("crv").asText(); // Should be P-256

			ECParameterSpec ecSpec = getCurveFromCrv(crv); // helper function below

			ECPoint ecPoint = new ECPoint(
					new BigInteger(1, decoder.decode(xString)),
					new BigInteger(1, decoder.decode(yString))
			);

			ECPublicKeySpec pubSpec = new ECPublicKeySpec(ecPoint, ecSpec);
			KeyFactory factory = KeyFactory.getInstance("EC");
			ECPublicKey pub = (ECPublicKey) factory.generatePublic(pubSpec);

			algorithm = Algorithm.ECDSA256(pub, null);
		} else {
			throw new IllegalArgumentException("Unsupported key type: " + kty);
		}

		JWTVerifier verifier = JWT.require(algorithm).build();

		try {
			decodedJwt = verifier.verify(jwt);
		}
		catch(SignatureVerificationException ex){
			throw new Exception("JWT Invalid signature", ex);
		}
		catch(AlgorithmMismatchException ex){
			throw new Exception("JWT Algorithm mismatch", ex);
		}
		catch(TokenExpiredException ex){
			throw new Exception("JWT Token expired", ex);
		}
		catch(InvalidClaimException ex){
			throw new Exception("JWT, one or more claims are invalid", ex);
		}
	}

	private String fetchJwk(String fetchUrl, RunContext ctx){
        String responseString = null;

        try {
			URI kidUri = new URI(fetchUrl);
			if (kidUri.getScheme() == null || kidUri.getScheme().equals("did")) {
				DidResolver didResolver = ctx.get(RunContextKey.DID_RESOLVER);
				DidResolution didResolution = didResolver.resolve(kidUri, new CachingDocumentLoader()); // Not using the default document loader options
				responseString = didResolution.getPublicKeyJwk();
			} else {
				CloseableHttpClient client = HttpClients.createDefault();
				HttpGet httpGet = new HttpGet(fetchUrl);

				CloseableHttpResponse response = client.execute(httpGet);

				if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
					HttpEntity entity = response.getEntity();
					responseString = EntityUtils.toString(entity, "UTF-8");
				}

				client.close();
			}
        }
        catch(Exception ex){
            responseString = null;
        }

        return responseString;
    }

	// Maps curve name from JWK to ECParameterSpec
	private static ECParameterSpec getCurveFromCrv(String crv) throws Exception {
		if ("P-256".equals(crv)) {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec("secp256r1"));
			return parameters.getParameterSpec(ECParameterSpec.class);
		}
		throw new IllegalArgumentException("Unsupported curve: " + crv);
	}

	public static final String ID = ExternalProofProbe.class.getSimpleName();

}