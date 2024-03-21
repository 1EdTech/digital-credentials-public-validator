package org.oneedtech.inspect.vc.verification;

import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import io.ipfs.multibase.Multibase;

import java.security.GeneralSecurityException;

public class Ed25519Signature2022VCDM20LdVerifier extends LdVerifier<Ed25519Signature2022SignatureSuite> {

    public Ed25519Signature2022VCDM20LdVerifier(ByteVerifier verifier) {

        super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2022, verifier, new URDNA2015Canonicalizer(Eddsa2022v2LdProof.builder()));
    }

    public Ed25519Signature2022VCDM20LdVerifier(byte[] publicKey) {

        this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
    }

    public Ed25519Signature2022VCDM20LdVerifier() {

        this((ByteVerifier) null);
    }

    public static boolean verify(byte[] signingInput, LdProof ldProof, ByteVerifier verifier) throws GeneralSecurityException {

        // verify

        String proofValue = ldProof.getProofValue();
        if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

        boolean verify;

        byte[] bytes = Multibase.decode(proofValue);
        verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA);

        // done

        return verify;
    }

    @Override
    public boolean verify(byte[] signingInput, LdProof ldProof) throws GeneralSecurityException {

        return verify(signingInput, ldProof, this.getVerifier());
    }

}

