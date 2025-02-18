package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.core.probe.RunContext.Key.JACKSON_OBJECTMAPPER;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.oneedtech.inspect.vc.status.bitstring.BitstringStatusListProbe;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * A Probe that verifies a credential's revocation status.
 *
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
     *
     *	If the AchievementCredential or EndorsementCredential has a “credentialStatus” property
     *	and the type of the CredentialStatus object is BitstringStatusListEntry, fetch the
     *	credential status following Bitstring Status List
     * https://w3c.github.io/vc-bitstring-status-list
     */

    String credentialId = crd.getJson().get("id").asText();
    JsonNode credentialStatus = crd.getJson().get("credentialStatus");
    if (credentialStatus != null) {
      if (credentialStatus.isArray()) {
        for (JsonNode status : credentialStatus) {
          ReportItems report = checkStatus(status, credentialId, ctx);
          if (report != null) {
            return report;
          }
        }
      } else {
        ReportItems status = checkStatus(credentialStatus, credentialId, ctx);
        if (status != null) {
          return status;
        }
      }
    }
    return success(ctx);
  }

  private ReportItems checkStatus(JsonNode credentialStatus, String credentialId, RunContext ctx)
      throws Exception {
    JsonNode type = credentialStatus.get("type");
    if (type == null) {
      return null;
    }
    if (type.asText().strip().equals("1EdTechRevocationList")) {
      JsonNode listID = credentialStatus.get("id");
      if (listID != null) {
        try {
          URL url = new URI(listID.asText().strip()).toURL();
          HttpURLConnection connection = (HttpURLConnection) url.openConnection();
          connection.setRequestProperty("Accept", MimeType.JSON.toString());
          try (InputStream is = connection.getInputStream()) {
            JsonNode revocList =
                ((ObjectMapper) ctx.get(JACKSON_OBJECTMAPPER)).readTree(is.readAllBytes());

            /* To check if a credential has been revoked, the verifier issues a GET request
             * to the URL of the issuer's 1EdTech Revocation List Status Method. If the
             * credential's id is in the list of revokedCredentials and the value of
             * revoked is true or ommitted, the issuer has revoked the credential. */

            if (credentialId != null) {
              List<JsonNode> list = JsonNodeUtil.asNodeList(revocList.get("revokedCredential"));
              if (list != null) {
                for (JsonNode item : list) {
                  String revID = item.get("id").asText();
                  JsonNode revoked = item.get("revoked");
                  if (revID != null
                      && revID.equals(credentialId)
                      && (revoked == null || revoked.asBoolean())) {
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
    } else if (type.asText().strip().equals("BitstringStatusListEntry")) {
      if (credentialStatus.hasNonNull("statusPurpose")
          && credentialStatus.get("statusPurpose").asText().strip().equals("revocation")) {
        return new BitstringStatusListProbe().run(credentialStatus, ctx);
      }
    }
    return null;
  }

  public static final String ID = RevocationListProbe.class.getSimpleName();
}
