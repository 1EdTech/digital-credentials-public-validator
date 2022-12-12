package org.oneedtech.inspect.vc;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Validation class for Open Badges 2.0 types
 */
public class Validation {
    private final String name;
    private final Assertion.ValueType type;
    private final boolean required;
    private final boolean many;
    private final List<String> mustContainOne;
    private final List<Validation> prerequisites;
    private final List<Assertion.Type> expectedTypes;
    private final boolean allowRemoteUrl;
    private final boolean allowDataUri;
    private final boolean fetch;
    private final String defaultType;
    private final boolean fullValidate;
    private MessageLevel messageLevel;
    private final boolean allowFlattenEmbeddedResource;

    public Validation(Builder builder) {
        this.name = builder.name;
        this.type = builder.type;
        this.required = builder.required;
        this.many = builder.many;
        this.mustContainOne = builder.mustContainOne;
        this.prerequisites = builder.prerequisites;
        this.expectedTypes = builder.expectedTypes;
        this.allowRemoteUrl = builder.allowRemoteUrl;
        this.allowDataUri = builder.allowDataUri;
        this.fetch = builder.fetch;
        this.defaultType = builder.defaultType;
        this.fullValidate = builder.fullValidate;
        this.messageLevel = builder.messageLevel;
        this.allowFlattenEmbeddedResource = builder.allowFlattenEmbeddedResource;
    }

    public String getName() {
        return name;
    }

    public Assertion.ValueType getType() {
        return type;
    }

    public boolean isRequired() {
        return required;
    }

    public boolean isMany() {
        return many;
    }

    public List<String> getMustContainOne() {
        return mustContainOne;
    }

    public List<Validation> getPrerequisites() {
        return prerequisites;
    }

    public List<Assertion.Type> getExpectedTypes() {
        return expectedTypes;
    }

    public boolean isAllowRemoteUrl() {
        return allowRemoteUrl;
    }

    public boolean isAllowDataUri() {
        return allowDataUri;
    }

    public boolean isFetch() {
        return fetch;
    }

    public String getDefaultType() {
        return defaultType;
    }

    public boolean isFullValidate() {
        return fullValidate;
    }

    public MessageLevel getMessageLevel() {
        return messageLevel;
    }

    public boolean isAllowFlattenEmbeddedResource() {
        return allowFlattenEmbeddedResource;
    }

    public enum MessageLevel {
        Warning,
        Error
    }

    public static class Builder {
        private String name;
        private Assertion.ValueType type;
        private boolean required;
        private boolean many;
        private List<String> mustContainOne;
        private List<Validation> prerequisites;
        private List<Assertion.Type> expectedTypes;
        private boolean allowRemoteUrl;
        private boolean allowDataUri;
        private boolean fetch;
        private String defaultType;
        private boolean fullValidate;
        private MessageLevel messageLevel;
        private boolean allowFlattenEmbeddedResource;

        public Builder() {
            this.mustContainOne = new ArrayList<>();
            this.prerequisites = new ArrayList<>();
            this.expectedTypes = new ArrayList<>();
            this.messageLevel = MessageLevel.Error;
            this.fullValidate = true; // by default, full validation
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder type(Assertion.ValueType type) {
            this.type = type;
            return this;
        }

        public Builder required(boolean required) {
            this.required = required;
            return this;
        }

        public Builder many(boolean many) {
            this.many = many;
            return this;
        }

        public Builder mustContainOne(List<String> elems) {
            this.mustContainOne = elems;
            return this;
        }

        public Builder mustContainOneType(List<Assertion.Type> types) {
            this.mustContainOne = types.stream().map(Assertion.Type::toString).collect(Collectors.toList());
            return this;
        }

        public Builder prerequisites(List<Validation> elems) {
            this.prerequisites = elems;
            return this;
        }

        public Builder prerequisite(Validation elem) {
            this.prerequisites = List.of(elem);
            return this;
        }

        public Builder expectedTypes(List<Assertion.Type> elems) {
            this.expectedTypes = elems;
            return this;
        }

        public Builder expectedType(Assertion.Type type) {
            this.expectedTypes = List.of(type);
            return this;
        }

        public Builder allowRemoteUrl(boolean allowRemoteUrl) {
            this.allowRemoteUrl = allowRemoteUrl;
            return this;
        }

        public Builder allowDataUri(boolean allowDataUri) {
            this.allowDataUri = allowDataUri;
            return this;
        }

        public Builder fetch(boolean fetch) {
            this.fetch = fetch;
            return this;
        }

        public Builder defaultType(Assertion.Type defaultType) {
            return defaultType(defaultType.toString());
        }

        public Builder defaultType(String defaultType) {
            this.defaultType = defaultType;
            return this;
        }

        public Builder fullValidate(boolean fullValidate) {
            this.fullValidate = fullValidate;
            return this;
        }

        public Builder messageLevel(MessageLevel messageLevel) {
            this.messageLevel = messageLevel;
            return this;
        }

        public Builder allowFlattenEmbeddedResource(boolean allowFlattenEmbeddedResource) {
            this.allowFlattenEmbeddedResource = allowFlattenEmbeddedResource;
            return this;
        }

        public Validation build() {
            return new Validation(this);
        }
    }
}
