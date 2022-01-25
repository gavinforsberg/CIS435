/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

package phase2;

import java.math.BigInteger;
import java.util.Arrays;
import static phase2.Common.*;
import phase2.Common.Role;


public class User {

    private String name;
    private Role role;

    private BigInteger msg, ks, hashBase;
    BigInteger[] pubKey = new BigInteger[2]; // (n, e)
    BigInteger[] privateKey = new BigInteger[2]; // (n, d)




    //Constructors

    User(String name, Role role, boolean fixedData) {

        this.name = name;
        this.role = role;

        if (fixedData) {
            msg = BigInteger.valueOf(17);
            ks = BigInteger.valueOf(5);
            hashBase = BigInteger.valueOf(13);
        } else {
            msg = BigInteger.valueOf((int)(Math.random() * 1000));
            ks = BigInteger.valueOf((int)(Math.random() * 1000));
            hashBase = BigInteger.valueOf((int)(Math.random() * 1000));
        }
        
    }

    User(String name, Role role) {
        this.name = name;
        this.role = role;
    }

    User(BigInteger msg, BigInteger ks, BigInteger hashBase) {
        this.msg = msg;
        this.ks = ks;
        this.hashBase = hashBase;
    }









    public void printDetails() {

        System.out.println(indent1 + "Original Msg from Sender (msg): " + getMsg());
        System.out.println(indent1 + "Random Session Key (Ks): "
                + getKs());
        System.out.println(indent1 + "Choose hash function with (hashBase): "
                + getHashBase());

    }

    @Override
    public String toString() {

        if (role.equals(Role.RECEIVER)) {

            return "Receiver {" + "name=" + name + ", msg=" + msg + ", ks=" + ks + ", hashBase=" + hashBase
                    + ", pubKey=" + Arrays.toString(pubKey) + ", privateKey=" + Arrays.toString(privateKey) + '}';
        }

        return "Sender {" + "name=" + name + ", msg=" + msg + ", ks=" + ks + ", hashBase=" + hashBase
                + ", pubKey=" + Arrays.toString(pubKey) + ", privateKey=" + Arrays.toString(privateKey) + '}';
    }

    




    //SETTERS & GETTERS
    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public BigInteger[] getPubKey() {
        return pubKey;
    }

    public void setPubKey(BigInteger[] pubKey) {
        this.pubKey = pubKey;
    }

    public BigInteger[] getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger[] privateKey) {
        this.privateKey = privateKey;
    }

    public BigInteger getMsg() {
        return msg;
    }

    public void setMsg(BigInteger msg) {
        this.msg = msg;
    }

    public BigInteger getKs() {
        return ks;
    }

    public void setKs(BigInteger ks) {
        this.ks = ks;
    }

    public BigInteger getHashBase() {
        return hashBase;
    }

    public void setHashBase(BigInteger hashBase) {
        this.hashBase = hashBase;
    }

}
