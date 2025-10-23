package org.velocitynetwork.contracts;


import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.StaticGasProvider;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.UUID.randomUUID;

public class VelocityNetworkMetadataRegistryFacadeImpl implements VelocityNetworkMetadataRegistryFacade {
    private VelocityNetworkMetadataRegistry metadataRegistryContract;
    private final String contractAddress;
    private final Web3j web3;
    private final Credentials credentials;

    public VelocityNetworkMetadataRegistryFacadeImpl(String rpcUrl, String privateKey, String contractAddress) {
        this(rpcUrl, privateKey, contractAddress, null, null, null);
    }

    public VelocityNetworkMetadataRegistryFacadeImpl(String rpcUrl, String privateKey, String contractAddress, String tokenEndpoint, String clientId, String clientSecret) {
        this.contractAddress = contractAddress;

        OkHttpClient.Builder clientBuilder = new OkHttpClient.Builder();

        if (tokenEndpoint !=null && clientId != null && clientSecret != null) {
            clientBuilder = clientBuilder.addInterceptor(new Interceptor() {
                private String accessToken = null;
                @Override public Response intercept(Interceptor.Chain chain) throws IOException {
                    Request originalRequest = chain.request();

                    if (this.accessToken == null) {
                        OkHttpClient authClient = new OkHttpClient()
                                .newBuilder()
                                .build();

                        // Create the request body
                        MediaType mediaType = MediaType.parse("application/json");
                        String authRequestJson = "{\"grant_type\":\"client_credentials\",\"audience\":\"https://velocitynetwork.node\",\"client_id\":\"" + clientId + "\",\"client_secret\":\"" + clientSecret + "\"}";
                        RequestBody authBody = RequestBody.Companion.create(authRequestJson, mediaType);

                        // Build the request object, with method, headers
                        Request authRequest = new Request.Builder()
                                .url(tokenEndpoint)
                                .method("POST", authBody)
                                .build();

                        // Perform the request, this potentially throws an IOException
                        Response authResponse = authClient.newCall(authRequest).execute();
                        // Read the body of the response into a hashmap
                        Map<String, Object> authResponseMap = new ObjectMapper().readValue(authResponse.body().byteStream(), HashMap.class);
                        // Read the value of the "access_token" key from the hashmap
                        this.accessToken = (String) authResponseMap.get("access_token");
                    }

                    Request authenticatedRequest = originalRequest.newBuilder()
                            .header("Authorization", "Bearer " + this.accessToken)
                            .build();

                    return chain.proceed(authenticatedRequest);
                }
            });
        }

        OkHttpClient client = clientBuilder.build();
        HttpService ethRpcService = new HttpService(rpcUrl, client);
        this.web3 = Web3j.build(ethRpcService);
        this.credentials = Credentials.create(privateKey);
    }

    public VelocityNetworkMetadataRegistry getMetadataRegistryContract() {
        if (this.metadataRegistryContract == null) {
            this.metadataRegistryContract = org.velocitynetwork.contracts.VelocityNetworkMetadataRegistry.load(
                    contractAddress,
                    web3,
                    credentials,
                    new StaticGasProvider(BigInteger.ZERO, BigInteger.valueOf(9_000_000))
            );
        }
        return this.metadataRegistryContract;
    }

    public List<VelocityNetworkMetadataRegistry.CredentialMetadata> getPaidEntries(List<VelocityNetworkMetadataRegistry.CredentialIdentifier> _entryIndexes, String traceId, String caoDid, String burnerDid) throws Exception {
        TransactionReceipt transactionReceipt = getMetadataRegistryContract().getPaidEntries(
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
