package org.oneedtech.inspect.vc.probe.did;

public class DidResolution {
    private final String publicKeyMultibase;
    private final String controller;

    DidResolution(Builder builder) {
        this.publicKeyMultibase =  builder.publicKeyMultibase;
        this.controller = builder.controller;
    }

    public String getPublicKeyMultibase() {
        return publicKeyMultibase;
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
        String controller;

        public Builder publicKeyMultibase(String publicKeyMultibase) {
            this.publicKeyMultibase = publicKeyMultibase;
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
