package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.core.probe.RunContext.Key.JACKSON_OBJECTMAPPER;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.MimeType;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A Probe that verifies a credential's revocation status.
 * @author mgylling
 */
public class RevocationListProbe extends Probe<Credential> {

	public RevocationListProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {

		/*
		 *	If the AchievementCredential or EndorsementCredential has a “credentialStatus” property
		 *	and the type of the CredentialStatus object is “1EdTechRevocationList”, fetch the
		 *	credential status from the URL provided. If the request is unsuccessful,
		 *	report a warning, not an error.
		 */

		JsonNode credentialStatus = crd.getJson().get("credentialStatus");
		if(credentialStatus != null) {
			JsonNode type = credentialStatus.get("type");
			if(type != null && type.asText().strip().equals("1EdTechRevocationList")) {
				JsonNode listID = credentialStatus.get("id");
				if(listID != null) {
					try {
						URL url = new URI(listID.asText().strip()).toURL();
						HttpURLConnection connection = (HttpURLConnection) url.openConnection();
						connection.setRequestProperty("Accept", MimeType.JSON.toString());
						try (InputStream is = connection.getInputStream()) {
					        JsonNode revocList = ((ObjectMapper)ctx.get(JACKSON_OBJECTMAPPER)).readTree(is.readAllBytes());

					        /* To check if a credential has been revoked, the verifier issues a GET request
					         * to the URL of the issuer's 1EdTech Revocation List Status Method. If the
					         * credential's id is in the list of revokedCredentials and the value of
					         * revoked is true or ommitted, the issuer has revoked the credential. */

					        JsonNode crdID = crd.getJson().get("id"); //TODO these != checks sb removed (trigger warning)
					        if(crdID != null) {
					        	List<JsonNode> list = JsonNodeUtil.asNodeList(revocList.get("revokedCredentials"));
					        	if(list != null) {
					        		for(JsonNode item : list) {
					        			JsonNode revID = item.get("id");
					        			JsonNode revoked = item.get("revoked");
					        			if(revID != null && revID.equals(crdID) && (revoked == null || revoked.asBoolean())) {
					        				return fatal("Credential has been revoked", ctx);
					        			}
					        		}
					        	}
					        }
						}
					} catch (Exception e) {
						return warning("Error when fetching credentialStatus resource " + e.getMessage(), ctx);
					}
				}
			}
		}
		return success(ctx);
	}

	public static final String ID = RevocationListProbe.class.getSimpleName();
}
