package org.oneedtech.inspect.vc.probe;

import static com.google.common.base.Strings.isNullOrEmpty;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Base64;
import java.util.Base64.Decoder;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.springframework.util.Base64Utils;

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
 * A Probe that verifies credential signatures 
 * @author mlyon
 */
public class SignatureVerifierProbe extends Probe<Credential> {
	
	public SignatureVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {
		try {
			verifySignature(crd);
		} catch (Exception e) {
			return fatal("Error verifying jwt signature: " + e.getMessage(), ctx);
		}	
					
		return success(ctx);
	}

	private void verifySignature(Credential crd) throws Exception {
        DecodedJWT decodedJwt = null;
		String jwt = crd.getJwt();
		if(isNullOrEmpty(jwt)) throw new IllegalArgumentException("invalid jwt");
		List<String> parts = Splitter.on('.').splitToList(jwt);
		if(parts.size() != 3) throw new IllegalArgumentException("invalid jwt");

		final Decoder decoder = Base64.getUrlDecoder();
		String joseHeader = new String(decoder.decode(parts.get(0)));

		ObjectMapper mapper = new ObjectMapper();
    	JsonNode headerObj = mapper.readTree(joseHeader);

		//MUST be "RS256"
		JsonNode alg = headerObj.get("alg");
		if(alg == null || !alg.textValue().equals("RS256")) { throw new Exception("alg must be present and must be 'RS256'"); }

		//TODO: decoded jwt will check timestamps, but shall we explicitly break these out?

		//Option 1, fetch directly from header
		JsonNode jwk = headerObj.get("jwk");

		//Option 2, fetch from a hosting url
		JsonNode kid = headerObj.get("kid");

		if(jwk == null && kid == null) { throw new Exception("Key must present in either jwk or kid value."); }
		if(kid != null){
			//TODO @Miles load jwk JsonNode from url and do the rest the same below.  Need to set up testing.
			String kidUrl = kid.textValue();
		}

		//Clean up may be required.  Currently need to cleanse extra double quoting.
		String modulusString = jwk.get("n").textValue();
		String exponentString = jwk.get("e").textValue();

		BigInteger modulus = new BigInteger(1, org.springframework.util.Base64Utils.decodeFromUrlSafeString(modulusString));
		BigInteger exponent = new BigInteger(1, org.springframework.util.Base64Utils.decodeFromUrlSafeString(exponentString));

		PublicKey pub = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));

		Algorithm algorithm = Algorithm.RSA256((RSAPublicKey)pub, null);
		JWTVerifier verifier = JWT.require(algorithm)
				.build(); //Reusable verifier instance
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
	
	public static final String ID = SignatureVerifierProbe.class.getSimpleName();

}