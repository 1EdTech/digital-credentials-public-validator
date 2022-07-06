package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.core.probe.RunContext.Key.JACKSON_OBJECTMAPPER;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Base64.Encoder;
import java.util.Map.Entry;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.StringUtils;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.rdf.Rdf;
import com.apicatalog.rdf.RdfDataset;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.bitcoin.core.Base58;
import com.google.common.io.BaseEncoding;

import io.setl.rdf.normalization.RdfNormalize;

/**
 * A Probe that verifies credential proofs 
 * @author mlyon
 */
public class ProofVerifierProbe extends Probe<Credential> {
	
	public ProofVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {
		
		try {
			//String document = fetchConanicalDocument(crd, C14n.URDNA2015, MediaType.N_QUADS, ctx);
			String document = "";
			String proof = fetchConanicalProof(crd, C14n.URDNA2015, MediaType.N_QUADS, ctx);
			//System.out.println(canonical);



			/*
			Encoder encoder1 = Base64.getEncoder();
			String testSignature = "z3MUt2ZuU8Byqivxh6GphEM65AFYyNaGYibm97xLTafM7uGufZQLKvJR8itZwxKskvtFM3CUty46v26DZidMNoQnM";
			String signature = encoder1.encodeToString(testSignature.getBytes());

			Encoder encoder2 = Base64.getEncoder();
			String testKey = "z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj";
			String key64 = encoder2.encodeToString(testKey.getBytes());
			String keyHex = Hex.toHexString(testKey.getBytes());

			boolean test = validate(
				keyHex, 
				signature, 
				"", 
				canonical
			);
			*/

			

			byte[] docHash = getBytes(document);
			byte[] proofHash = getBytes(proof);
			// concatenate hash of c14n proof options and hash of c14n document
			byte[] combined = mergeArrays(proofHash, docHash);

			boolean test = testSigner(combined);
			

			boolean stophere = true;
			//TODO if proofs fail, report OutCome.Fatal
			//return fatal("msg", ctx);
			
		} catch (Exception e) {
			return exception(e.getMessage(), crd.getResource());
		}										
		return success(ctx);
	}

	private String fetchConanicalDocument(Credential crd, C14n algo, MediaType mediaType, RunContext ctx) throws Exception {
		
		//clone the incoming credential object so we can modify it freely
		ObjectMapper mapper = (ObjectMapper)ctx.get(JACKSON_OBJECTMAPPER);
		JsonNode copy = mapper.readTree(crd.getJson().toString());
		
		//remove proof
		((ObjectNode)copy).remove("proof");
				
		//create JSON-P Json-LD instance
		JsonDocument jsonLdDoc = JsonDocument.of(new StringReader(copy.toString()));
				
		//create rdf and normalize //TODO add DocumentLoader to cache contexts
		RdfDataset dataSet = JsonLd.toRdf(jsonLdDoc).ordered(true).get();
		RdfDataset normalized = RdfNormalize.normalize(dataSet);
		
		//serialize to string
		ByteArrayOutputStream os = new ByteArrayOutputStream();
        Rdf.createWriter(mediaType, os).write(normalized);
        String result = StringUtils.stripTrailing(os.toString());
                
		return result;
	}

	private String fetchConanicalProof(Credential crd, C14n algo, MediaType mediaType, RunContext ctx) throws Exception {
		
		//clone the incoming credential object so we can modify it freely
		ObjectMapper mapper = (ObjectMapper)ctx.get(JACKSON_OBJECTMAPPER);
		JsonNode copy = mapper.readTree(crd.asJson().toString());

		//Get the context node to stitch back in.
		JsonNode context = copy.get("@context");

		//Pull out and use proof node only
		JsonNode proof = copy.get("proof");

		//TODO: Make this better at discarding all, but the linked data proof method.
		if(proof.isArray()){
			proof = proof.get(0);
		}

		//remove these if they exist
		((ObjectNode)proof).remove("jwt");
		((ObjectNode)proof).remove("signatureValue");
		((ObjectNode)proof).remove("proofValue");

		JsonNode newNode = mapper.createObjectNode();
		((ObjectNode) newNode).set("@context", context);
		//Try to structure this 'to the letter' per a slack with Markus
		//((ObjectNode) newNode).set("proof", proof);

		//So that we don't remove nodes while iterating over it save all nodes
		Iterator<Entry<String,JsonNode>> iter = proof.fields();
		while (iter.hasNext()) {
			Entry<String,JsonNode> next = iter.next();
			((ObjectNode) newNode).set(next.getKey(), next.getValue());
		}
				
		//create JSON-P Json-LD instance
		JsonDocument jsonLdDoc = JsonDocument.of(new StringReader(newNode.toString()));
				
		//create rdf and normalize
		RdfDataset dataSet = JsonLd.toRdf(jsonLdDoc).ordered(true).get();
		RdfDataset normalized = RdfNormalize.normalize(dataSet);
		
		//serialize to string
		ByteArrayOutputStream os = new ByteArrayOutputStream();
        Rdf.createWriter(mediaType, os).write(normalized);
        String result = StringUtils.stripTrailing(os.toString());
                
		return result;
	}

	private boolean validate(String pubkey, String signature, String timestamp, String message) throws Exception {
		//TODO: continue this implementation.
		//Pulled in bouncy castle library and made sure this sample compiled only.
		final var provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		final var byteKey = Hex.decode(pubkey);
		final var pki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), byteKey);
		final var pkSpec = new X509EncodedKeySpec(pki.getEncoded());
		final var kf = KeyFactory.getInstance("ed25519", provider);
		final var publicKey = kf.generatePublic(pkSpec);
		final var signedData = Signature.getInstance("ed25519", provider);
		signedData.initVerify(publicKey);
		//Temporarily remove timestamp
		signedData.update(timestamp.getBytes());
		signedData.update(message.getBytes());
		return signedData.verify(Hex.decode(signature));
	}

	private boolean testSigner(byte[] concatBytes) throws Exception {


		final var provider = new BouncyCastleProvider();
		Security.addProvider(provider);

		//var publicKeyBytes = Base64.getUrlDecoder().decode("z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj");
		//var publicKeyBytes = Base64.getUrlDecoder().decode("6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj");


		//var publicKeyBytes = Base58.decode("z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj");
		//Key with the first chracter stripped
		//var publicKeyBytes = Base58.decode("6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj");


		//A working sample key
		//var publicKeyBytes = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");




		//Base 58 decode minus the z
		var publicKeyBytes = Base58.decode("6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj");
		//The slice out the first two array elements (???)
		byte[] slicedArray = Arrays.copyOfRange(publicKeyBytes, 2, 34); 



		final var pki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), slicedArray);
		final var pkSpec = new X509EncodedKeySpec(pki.getEncoded());
		final var kf = KeyFactory.getInstance("ed25519", provider);
		final var publicKey = kf.generatePublic(pkSpec);
		final var signedData = Signature.getInstance("ed25519", provider);
		signedData.initVerify(publicKey);
		signedData.update(concatBytes);

		boolean whatever = true;


		//Final step, add signature.

		//Need to do this in java
		//const signatureBytes = base58btc.decode(proofValue.substr(1));


		var signatureBytes = Base58.decode("3MUt2ZuU8Byqivxh6GphEM65AFYyNaGYibm97xLTafM7uGufZQLKvJR8itZwxKskvtFM3CUty46v26DZidMNoQnM");

		return signedData.verify(signatureBytes);




/*
		String hexEncodedPubKey = "z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj";

        // Convert to JCA format
        byte[] pubKeyBytes = BaseEncoding.base16().lowerCase().decode(hexEncodedPubKey);
        SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), pubKeyBytes);


		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
		KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", provider);
		PublicKey pk = keyFactory.generatePublic(keySpec);

		
*/




		/*
		var test = new RSADigestSigner(digest, digestOid)

		test.verifySignature(signature);
		*/


		
		
		
		
	}

	/*
	private boolean testSigner3(String message, byte[] concateBytes) throws Exception {


        // Test case defined in https://www.rfc-editor.org/rfc/rfc8037
        var msg = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc".getBytes(StandardCharsets.UTF_8);
        var expectedSig = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

        var privateKeyBytes = Base64.getUrlDecoder().decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
        var publicKeyBytes = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        var privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        // Generate new signature
        Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        byte[] signature = signer.generateSignature();
        var actualSignature = Base64.getUrlEncoder().encodeToString(signature).replace("=", "");

        LOG.info("Expected signature: {}", expectedSig);
        LOG.info("Actual signature  : {}", actualSignature);

        assertEquals(expectedSig, actualSignature);


		return true;
	}
	*/
	

	private byte[] getBytes(String value) throws Exception{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(
			value.getBytes(StandardCharsets.UTF_8)
		);
	}

	private static byte[] mergeArrays(final byte[] array1, byte[] array2) {
		byte[] joinedArray = Arrays.copyOf(array1, array1.length + array2.length);
		System.arraycopy(array2, 0, joinedArray, array1.length, array2.length);
		return joinedArray;
	}
	
	private enum C14n {
		URDNA2015
	}

	public static final String ID = ProofVerifierProbe.class.getSimpleName();
}
