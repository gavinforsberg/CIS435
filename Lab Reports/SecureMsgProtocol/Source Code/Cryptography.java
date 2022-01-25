/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

 package phase2;

import java.math.BigInteger;
import static phase2.Common.*;


public class Cryptography {

    private RSA rsa;

    //CONSTRUCTOR
    Cryptography() {
        System.out.println(indent2 + "Run Cryptography --------");
        rsa = new RSA();
        System.out.println(indent2 + rsa.toString());
    }
   
    // Use the mapping provided in our ICE, and you can modify the header of this method
    static public BigInteger CBC() {
     
        //TODO
        return BigInteger.ZERO;
    }

    static public BigInteger hash(BigInteger msg, BigInteger hashBase) {
        BigInteger msgCopy = msg;
        BigInteger hashValue = msgCopy.mod(hashBase);
        return hashValue;
    }

    static public BigInteger shift(BigInteger msg, BigInteger ks, Boolean encrypt) {
        if (encrypt) {
            return msg.add(ks);
        }
        return msg.subtract(ks);
    }

    //(n, e)
    public BigInteger[] getPublicKey() {
        BigInteger n = rsa.getN();
        BigInteger e = rsa.getE();
        BigInteger[] result = new BigInteger[2];
        result[0] = n;
        result[1] = e;
        return result;
    }

    // (n, d)
    public BigInteger[] getPrivateKey(/*BigInteger[] privateKey*/) {
       BigInteger n = rsa.getN();
       BigInteger d = rsa.getD();
       BigInteger[] result = new BigInteger[2];
        result[0] = n;
        result[1] = d;
        return result;
    }

    //[n, e]
    //[n, d]
    static public BigInteger rsaEncrypt(BigInteger[] key, BigInteger clearMsg) {
        return clearMsg.modPow(key[1], key[0]); // m^e (mod n) = c
    }

    static public BigInteger rsaDecrypt(BigInteger[] key, BigInteger encryptedMsg) {
        return encryptedMsg.modPow(key[1], key[0]); // (c^d) % n
    }
}