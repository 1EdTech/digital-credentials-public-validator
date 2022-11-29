package org.oneedtech.inspect.vc.util;

import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.IllformedLocaleException;
import java.util.List;
import java.util.Locale;

import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.io.Resources;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;

/**
 * Validator for ValueType. Translated into java from PrimitiveValueValidator in validation.py
 */
public class PrimitiveValueValidator {

    public static boolean validateBoolean(JsonNode value) {
        return value.isValueNode() && value.isBoolean();
    }

    public static boolean validateCompactIri(JsonNode value) {
        if (value.asText().equals("id") || validateIri(value)) {
            return true;
        }

        return false;
    }

    public static boolean validateDataUri(JsonNode value) {
        try {
            URI uri = new URI(value.asText());
            return "data".equalsIgnoreCase(uri.getScheme());
        } catch (Throwable ignored) {
        }
        return false;
    }

    public static boolean validateDataUriOrUrl(JsonNode value) {
        return validateUrl(value) || validateDataUri(value);
    }

    public static boolean validateDatetime(JsonNode value) {
        try {
            DateTimeFormatter.ISO_INSTANT.parse(value.asText());
            return true;
        } catch (DateTimeParseException | NullPointerException ignored) {
        }
        return false;
    }

    public static boolean validateEmail(JsonNode value) {
        return value.asText().matches("(^[^@\\s]+@[^@\\s]+$)");
    }

    public static boolean is_hashed_identity_hash(JsonNode value) {
        return value.asText().matches("md5\\$[\\da-fA-F]{32}$") || value.asText().matches("sha256\\$[\\da-fA-F]{64}$");
    }

    /**
     * Validates that identity is a string. More specific rules may only be enforced at the class instance level.
     * @param value
     * @return
     */
    public static boolean validateIdentityHash(JsonNode value) {
        return validateText(value);
    }

    /**
     * Checks if a string matches an acceptable IRI format and scheme. For now, only accepts a few schemes,
     * 'http', 'https', blank node identifiers, and 'urn:uuid'

     * @return
     */
    public static boolean validateIri(JsonNode value) {
        return validateUrl(value) || value.asText().matches("^_:") || value.asText().matches("^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    }

    public static boolean validateLanguage(JsonNode value) {
        try {
            return validateText(value) && new Locale.Builder().setLanguageTag(value.asText()).build() != null;
        } catch (IllformedLocaleException ignored) {
            // value is not a valid locale
        }
        return false;
    }

    public static boolean validateMarkdown(JsonNode value) {
        return validateText(value);
    }

    public static boolean validateRdfType(JsonNode value) {
        if (!validateText(value)) {
            return false;
        }

        ObjectMapper mapper = new ObjectMapper(); // TODO: get from RunContext
        JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper); // TODO: get from RunContext

        try {
            JsonNode node = mapper.readTree(Resources.getResource("contexts/ob-v2p0.json"));
            ObjectReader readerForUpdating = mapper.readerForUpdating(node);
            JsonNode merged = readerForUpdating.readValue("{\"type\": \"" + value.asText() + "\"}");

            JsonDocument jsonDocument = JsonDocument.of(new StringReader(merged.toString()));
            JsonNode expanded = mapper.readTree(JsonLd.expand(jsonDocument).get().toString());

            return validateIri(JsonNodeUtil.asNodeList(expanded, "$[0].@type[0]", jsonPath).get(0));

        } catch (NullPointerException | IOException | JsonLdError e) {
            return false;
        }
    }

    public static boolean validateTelephone(JsonNode value) {
        return value.asText().matches("^\\+?[1-9]\\d{1,14}(;ext=\\d+)?$");
    }

    public static boolean validateText(JsonNode value) {
        return value.isValueNode() && value.isTextual();
    }

    public static boolean validateTextOrNumber(JsonNode value) {
        return value.isValueNode() && value.isTextual() || value.isNumber();
    }

    public static boolean validateUrl(JsonNode value) {
        if (!value.isValueNode()) {
            return false;
        }

        try {
            new URL(value.asText());
            return true;
        } catch (MalformedURLException ignored) {
            // value is not a valid URL
        }
        return false;
    }

    public static boolean validateUrlAuthority(JsonNode value) {
        if (!validateText(value)) {
            return false;
        }

        URI testUri;
        try {
            testUri = new URI("http://" + value.asText() + "/test");
            String host = testUri.getHost();
            if (host == null || !host.matches("(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{0,62}[a-zA-Z0-9]\\.)+[a-zA-Z]{2,63}$)")) {
                return false;
            }
            return testUri.getScheme().equals("http") && host.equals(value.asText()) && testUri.getPath().equals("/test") && testUri.getQuery() == null;
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
