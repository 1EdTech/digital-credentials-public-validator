package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.core.probe.RunContext.Key.JACKSON_OBJECTMAPPER;

import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
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
			String canonical = canonicalize(crd, C14n.URDNA2015, MediaType.N_QUADS, ctx);
			//System.out.println(canonical);
			
			//TODO if proofs fail, report OutCome.Fatal
			//return fatal("msg", ctx);
			
		} catch (Exception e) {
			return exception(e.getMessage(), crd.getResource());
		}										
		return success(ctx);
	}

	private String canonicalize(Credential crd, C14n algo, MediaType mediaType, RunContext ctx) throws Exception {
		
		//clone the incoming credential object so we can modify it freely
		ObjectMapper mapper = (ObjectMapper)ctx.get(JACKSON_OBJECTMAPPER);
		JsonNode copy = mapper.readTree(crd.asJson().toString());
		
		//remove proof
		((ObjectNode)copy).remove("proof");
				
		//create JSON-P Json-LD instance
		JsonDocument jsonLdDoc = JsonDocument.of(new StringReader(copy.toString()));
				
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
		signedData.update(timestamp.getBytes());
		signedData.update(message.getBytes());
		return signedData.verify(Hex.decode(signature));
	}
	
	private enum C14n {
		URDNA2015
	}

	public static final String ID = ProofVerifierProbe.class.getSimpleName();
}
