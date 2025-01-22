package org.oneedtech.inspect.vc.probe.did;

public class DidResolution {
    private final String publicKeyMultibase;
    private final String publicKeyJwk;
    private final String controller;

    DidResolution(Builder builder) {
        this.publicKeyMultibase =  builder.publicKeyMultibase;
        this.publicKeyJwk = builder.publicKeyJwk;
        this.controller = builder.controller;
    }

    public String getPublicKeyMultibase() {
        return publicKeyMultibase;
    }

    public String getPublicKeyJwk() {
        return publicKeyJwk;
    }

    public String getController() {
        return controller;
    }

    public static Builder builder() {
        return new Builder();
    }

    // builder
    public static class Builder {
        String publicKeyMultibase;
        String publicKeyJwk;
        String controller;

        public Builder publicKeyMultibase(String publicKeyMultibase) {
            this.publicKeyMultibase = publicKeyMultibase;
            return this;
        }

        public Builder publicKeyJwk(String publicKeyJwk) {
            this.publicKeyJwk = publicKeyJwk;
            return this;
        }

        public Builder controller(String controller) {
            this.controller = controller;
            return this;
        }

        public DidResolution build() {
            return new DidResolution(this);
        }
    }
}
