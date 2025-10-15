package org.velocitynetwork.contracts;

import com.authlete.cbor.*;
import com.authlete.cose.COSEKey;

import java.util.Base64;
import java.util.List;
import java.util.Map;

public class COSERSAKey extends COSEKey {
    private byte[] n;
    private byte[] e;

    public COSERSAKey(List<? extends CBORPair> pairs) {
        super(pairs);
        this.validateParameters(pairs);
    }

    private void validateParameters(List<? extends CBORPair> pairs) {
        for(CBORPair pair : pairs) {
            this.validateParameter(pair);
        }
    }

    private void validateParameter(CBORPair pair) {
        CBORItem label = pair.getKey();
        if (label instanceof CBORInteger) {
            this.validateKnownParameter((Integer)((CBORInteger)label).getValue(), pair.getValue());
        }
    }

    private void validateKnownParameter(int label, CBORItem value) {
        switch (label) {
            case -1:
                this.n = validateN(value);
                break;
            case -2:
                this.e = validateE(value);
                break;
        }
    }

    private static byte[] validateN(CBORItem value) {
        if (value instanceof CBORByteArray) {
            return (byte[])getRawValue(value);
        } else {
            throw new IllegalArgumentException("n (-1) must be a byte string.");
        }
    }

    private static byte[] validateE(CBORItem value) {
        if (value instanceof CBORByteArray) {
            return (byte[])getRawValue(value);
        } else {
            throw new IllegalArgumentException("e (-1) must be a byte string.");
        }
    }

    public boolean isPrivate() {
        return false;
    }

    protected void addJwkProperties(Map<String, Object> map) {
        if (this.n != null) {
            map.put("n", encodeByBase64Url(this.n));
        }

        if (this.e != null) {
            map.put("e", encodeByBase64Url(this.e));
        }
    }

    static Object getRawValue(CBORItem item) {
        return ((CBORValue)item).getValue();
    }

    static String encodeByBase64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
