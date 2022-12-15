package org.oneedtech.inspect.vc.probe.validation;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.MimeType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.util.PrimitiveValueValidator;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Image validation for Open Badges 2.0
 * Maps to "IMAGE_VALIDATION" task in python implementation
 * @author xaracil
 */
public class ValidationImagePropertyProbe extends ValidationPropertyProbe {

    public ValidationImagePropertyProbe(String credentialType, Validation validation) {
        this(credentialType, validation, true);
    }

    public ValidationImagePropertyProbe(String credentialType, Validation validation, boolean fullValidate) {
        super(ID, credentialType, validation, fullValidate);
    }

    @Override
    protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
        // Could not load and validate image in node
        return success(ctx);
    }

    @Override
    protected ReportItems validate(JsonNode node, RunContext ctx) {
        if (node.isArray()) {
            return error("many images not allowed", ctx);
        }
        String url = node.isObject() ? node.get("id").asText() : node.asText();
        if (PrimitiveValueValidator.validateDataUri(node)) {
            if (!validation.isAllowDataUri()) {
                return error("Image in node " + node + " may not be a data URI.", ctx);
            }

            // check mime types
            final Pattern pattern = Pattern.compile("(^data):([^,]{0,}?)?(base64)?,(.*$)");
            final Matcher matcher = pattern.matcher(url);
            if (matcher.matches()) {
                MimeType mimeType = new MimeType(matcher.toMatchResult().group(2));
                if (!allowedMimeTypes.contains(mimeType)) {
                    return error("Data URI image does not declare any of the allowed PNG or SVG mime types in " + node.asText(), ctx);
                }
            }
        } else if (!url.isEmpty()) {
            try {
                UriResource uriResource = resolveUriResource(ctx, url);
                // TODO: load resource from cache
                // TODO: check accept type -> 'Accept': 'application/ld+json, application/json, image/png, image/svg+xml'
                uriResource.asByteSource();
            } catch (Throwable t) {
                return fatal(t.getMessage(), ctx);
            }
        }
        return success(ctx);
    }

    private static final List<MimeType> allowedMimeTypes = List.of(MimeType.IMAGE_PNG, MimeType.IMAGE_SVG);
    public static final String ID = ValidationImagePropertyProbe.class.getSimpleName();

}
