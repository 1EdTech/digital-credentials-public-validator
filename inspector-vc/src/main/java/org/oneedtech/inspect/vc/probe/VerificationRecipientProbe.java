package org.oneedtech.inspect.vc.probe;

import java.util.List;

import org.bouncycastle.crypto.digests.GeneralDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Assertion;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Recipient Verification probe for Open Badges 2.0
 * Maps to "VERIFY_RECIPIENT_IDENTIFIER" task in python implementation
 * @author xaracil
 */
public class VerificationRecipientProbe extends Probe<Assertion> {
    final String profileId;

    public VerificationRecipientProbe(String profileId) {
        super(ID);
        this.profileId = profileId;
    }

    @Override
    public ReportItems run(Assertion assertion, RunContext ctx) throws Exception {
        ReportItems warnings = new ReportItems();
        JsonNode recipientNode = assertion.getJson().get("recipient");

        JsonLdGeneratedObject profileObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProve.getId(profileId));
        JsonNode profileNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER)).readTree(profileObject.getJson());

        String type = recipientNode.get("type").asText().strip();
        if (!allowedTypes.contains(type)) {
            warnings = warning("Recipient identifier type " + type + " in assertion " + assertion.getJson().toString() + " is not one of the recommended types", ctx);
        }

        JsonNode typeNode = profileNode.get(type);
        if (JsonNodeUtil.isEmpty(typeNode)) {
            return new ReportItems(List.of(warnings, error("Profile identifier property of type " + typeNode + " not found in submitted profile " + profileId, ctx)));
        }

        JsonNode hashNode = recipientNode.get("hashed");
        List<String> currentTypes = JsonNodeUtil.asStringList(typeNode);
        String identity = recipientNode.get("identity").asText().strip().toLowerCase();
        String confirmedId = null;
        if (JsonNodeUtil.isNotEmpty(hashNode) && hashNode.asBoolean()) {
            String salt = recipientNode.get("salt").asText().strip();
            for (String possibleId : currentTypes) {
                if (hashMatch(possibleId, identity, salt)) {
                    confirmedId = possibleId;
                    break;
                }
            }
            if (confirmedId == null) {
                return new ReportItems(List.of(warnings, error("Profile " + profileId + " identifier(s) " + currentTypes + " of type " + typeNode.toString() + " did not match assertion " +  assertion.getId() + " recipient hash " + identity + ".", ctx)));
            }
        } else if (currentTypes.contains(identity)) {
            confirmedId = identity;
        } else {
            return new ReportItems(List.of(warnings, error("Profile " + profileId + " identifier " + currentTypes + " of type " + typeNode.toString()  + " did not match assertion " +  assertion.getId() + " recipient value " + identity, ctx)));
        }

        return new ReportItems(List.of(warnings, success(ctx)));
    }

    private boolean hashMatch(String possibleId, String identity, String salt) throws Exception {
        String text = possibleId + salt;
        GeneralDigest digest = null;
        if (identity.startsWith("md5")) {
            digest = new MD5Digest();
        } else if (identity.startsWith("sha256")) {
            digest = new SHA256Digest();
        } else {
            throw new IllegalAccessException("Cannot interpret hash type of " + identity);
        }
        digest.update(text.getBytes(), 0, text.length());
        byte[] digested = new byte[digest.getDigestSize()];
        digest.doFinal(digested, 0);
        return new String(Hex.encode(digested)).equals(identity);
    }

    private static final List<String> allowedTypes = List.of("id", "email", "url", "telephone");
    public static final String ID = VerificationRecipientProbe.class.getSimpleName();

}
