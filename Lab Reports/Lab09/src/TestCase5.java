/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

 package phase1Base;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1Base.Common.*;

public class TestCase5 {

    public static void test() {

        //Initialize Sender (Amy)
        boolean fixedData = false;
        if (fixedData) {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Sender (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Sender (Random Data) "));
        }
        User amySender = createSender("Amy", fixedData);
        getRSAKeys(amySender);
        System.out.println("==> Sender's Status" + " | " + amySender.toString() + "\n");

        //Initialize Receiver (Bob)
        if (fixedData) {
            System.out.println(caseSeperator("*", "CASE #0_2 | Initialize Receiver (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_2 | Initialize Receiver (Random Data) "));
        }
        User bobReceiver = createReceiver("Bob");
        // getRSAKeys(bobReceiver);
        System.out.println("==> Receiver's Status" + " | " + bobReceiver.toString() + "\n");

        //Sender Encrypts message
        System.out.println(caseSeperator("*", "CASE #5: Suppose Sender wants to send Receiver a message with digital signature"));
        System.out.println(caseSeperator("+", "Sender Operations"));
        BigInteger[] payload = senderCase5(amySender, bobReceiver);
        System.out.println("==> Sender sends out : | " + Arrays.toString(payload) + "\n");
        
        //Receiver Decrypts message
        System.out.println(caseSeperator("+", "Receiver Operations"));
        /*BigInteger msg = */receiverCase5(bobReceiver, amySender, payload);
        // System.out.println("==> Receiver receives and verifies msg = | " + msg + "\n");

    }

    public static User createSender(String name, boolean fixedData) {
        step++;
        System.out.println("\n--- Step #" + step + ": START - Sender generates\t" + padding);
        User sender = new User("Amy", Common.Role.SENDER, fixedData);
        sender.setHashBase(BigInteger.valueOf(13));
        System.out.println(indent1 + sender.toString());
        sender.printDetails();
        System.out.println("--- Step #" + step + ": END of this Step \t\t" + padding + "\n");
        return sender;
    }

    public static User createReceiver(String name) {
        step = 1;
        System.out.println("\n--- Step #" + step + ": START - Receiver generates\t" + padding);
        User receiver = new User("Bob", Common.Role.RECEIVER);
        receiver.setHashBase(BigInteger.valueOf(13));
        System.out.println(indent1 + receiver.toString());
        receiver.printDetails();
        System.out.println("--- Step #" + step + ": END of this Step \t\t" + padding + "\n");
        return receiver;
    }

    public static void getRSAKeys(User user) {

        step++;
        System.out.println("\n--- Step #" + step + ": START - getRSAKeys()\t" + padding);
        int subStep = 1;
        System.out.println("--- Step #" + step + "-" + subStep + ": Run RSA " + "------------");
        Cryptography crypto = new Cryptography();
        subStep++;
        System.out.println("\n--- Step #" + step + "-" + subStep + ": Gets RSA keys" + "------------");
        user.setPubKey(crypto.getPublicKey());
        user.setPrivateKey(crypto.getPrivateKey());
        System.out.println(indent2 + "pubKey: " + Arrays.toString(user.getPubKey()));
        System.out.println(indent2 + "privateKey: " + Arrays.toString(user.getPrivateKey()));
        System.out.println("--- Step #" + step + ": END of getRSAKeys() \t" + padding + "\n");
    }

    public static BigInteger[] senderCase5(User sender, User receiver) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Sender should apply a hash function to the message and then encrypt the result with its private key.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should Pa-(H(Msg))-> cipher");
        return senderOperationsCase5(sender, receiver);
    }

    public static void receiverCase5(User receiver, User sender, BigInteger[] payload) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives payload = " + Arrays.toString(payload));
        System.out.println(indent2 + "Msg received = " + payload[0]);
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Receiver should decrypt the cipher with the sender's public key and compare that to a hash of the message.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should Pa+(cipher) ==  H(Msg)");
        receiverOperationsCase5(receiver, sender, payload);
    }
  
    private static BigInteger[] senderOperationsCase5(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase5 ----------------");
        System.out.println(indent2 + "senderPrivateKeyN = " + sender.getPrivateKey()[0]);
        System.out.println(indent2 + "senderPrivateKeyD = " + sender.getPrivateKey()[1]);
        System.out.println(indent2 + "senderHashBase = " + sender.getHashBase());

        BigInteger msg = sender.getMsg();
        BigInteger hash = Cryptography.hash(msg, sender.getHashBase());
        BigInteger enc = Cryptography.rsaEncrypt(sender.getPrivateKey(), hash);
        BigInteger[] payload = new BigInteger[2];
        payload[0] = msg;
        payload[1] = enc;

        System.out.println(indent2 + "Msg = " + msg);
        System.out.println(indent2 + "H(Msg) = " + hash);
        System.out.println(indent2 + "Pa-(H(Msg)) = " + enc);
        System.out.println(indent2 + "------------------End | senderOperationsCase5 ----------------");
        return payload;

    }

    private static void receiverOperationsCase5(User receiver, User sender, BigInteger[] payload) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase5 ----------------");
        System.out.println(indent2 + "senderPubKeyN = " + sender.getPubKey()[0]);
        System.out.println(indent2 + "senderPubKeyE = " + sender.getPubKey()[1]);
        System.out.println(indent2 + "receiverHashBase = " + receiver.getHashBase());

        BigInteger msg = payload[0];
        BigInteger hash1 = Cryptography.rsaDecrypt(sender.getPubKey(), payload[1]);
        BigInteger hash2 = Cryptography.hash(msg, receiver.getHashBase());

        System.out.println(indent2 + "Pa+(cipher) = " + hash1);
        System.out.println(indent2 + "H2(Msg) = " + hash2);

        if (hash1.equals(hash2)) {
            System.out.println(indent2 + "Hashes match. Message verified. Message is: " + msg);
            receiver.setMsg(msg);
        } else {
            System.out.println(indent2 + "Hashes don't match. Message could not be verified.");
        }
        
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "------------------ End | receiverOperationsCase5 ----------------\n");
    }
}