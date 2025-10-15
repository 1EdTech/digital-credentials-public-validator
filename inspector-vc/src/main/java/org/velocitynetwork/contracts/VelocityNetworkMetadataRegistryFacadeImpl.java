package org.velocitynetwork.contracts;


import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.StaticGasProvider;

import java.math.BigInteger;
import java.util.List;

import static java.util.UUID.randomUUID;

public class VelocityNetworkMetadataRegistryFacadeImpl implements VelocityNetworkMetadataRegistryFacade {
    private VelocityNetworkMetadataRegistry metadataRegistryContract;

    public VelocityNetworkMetadataRegistryFacadeImpl(String rpcUrl, String privateKey, String contractAddress) {
        Web3j web3 = Web3j.build(new HttpService(rpcUrl));
        Credentials credentials = Credentials.create(privateKey);
        this.metadataRegistryContract = org.velocitynetwork.contracts.VelocityNetworkMetadataRegistry.load(
                contractAddress,
                web3,
                credentials,
                new StaticGasProvider(BigInteger.ZERO, BigInteger.valueOf(9_000_000))
        );
    }

    public List<VelocityNetworkMetadataRegistry.CredentialMetadata> getPaidEntries(List<VelocityNetworkMetadataRegistry.CredentialIdentifier> _entryIndexes, String traceId, String caoDid, String burnerDid) throws Exception {
        TransactionReceipt transactionReceipt = this.metadataRegistryContract.getPaidEntries(
                _entryIndexes,
                randomUUID().toString(),
                burnerDid,
                burnerDid
        ).send();
        List<VelocityNetworkMetadataRegistry.GotCredentialMetadataEventResponse> credentialMetadataEvents =
                VelocityNetworkMetadataRegistry.getGotCredentialMetadataEvents(transactionReceipt);
        return credentialMetadataEvents.get(credentialMetadataEvents.size() - 1).credentialMetadataList;
    }
}
