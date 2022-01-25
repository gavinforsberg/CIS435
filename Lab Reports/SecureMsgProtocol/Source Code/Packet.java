package phase2;

import java.math.BigInteger;

public class Packet {

    private BigInteger encKs;   // ks
    private BigInteger encMsg; // cipher
    private BigInteger encDigSig;   //ks(DS)

    Packet() {
        encKs = BigInteger.ZERO;
        encMsg = BigInteger.ZERO;
        encDigSig = BigInteger.ZERO;
    }

    public BigInteger getEncKs() {
        return encKs;
    }

    public void setEncKs(BigInteger encKs) {
        this.encKs = encKs;
    }

    public BigInteger getCipher() {
        return encMsg;
    }
    
    public void setCipher(BigInteger cipher) {
        this.encMsg = cipher;
    }

    public BigInteger getEncDigSig() {
        return encDigSig;
    }

    public void setEncDigSig(BigInteger encDigSig) {
        this.encDigSig = encDigSig;
    }

    @Override
    public String toString() {
        return "Packet:\n\tCipher 'Ks(m)' = " + encMsg + "\n\tDigital Signature 'Ks(Ka-(H(m)))' = " + encDigSig + "\n\tEncrypted Ks 'Kb+(Ks)' = " + encKs + "\n";
    }
}
