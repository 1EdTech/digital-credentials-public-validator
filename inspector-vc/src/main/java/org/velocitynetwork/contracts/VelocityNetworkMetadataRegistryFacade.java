package org.velocitynetwork.contracts;

import java.util.List;

public interface VelocityNetworkMetadataRegistryFacade {
    List<VelocityNetworkMetadataRegistry.CredentialMetadata> getPaidEntries(List<VelocityNetworkMetadataRegistry.CredentialIdentifier> _entryIndexes, String traceId, String caoDid, String burnerDid) throws Exception;
}
