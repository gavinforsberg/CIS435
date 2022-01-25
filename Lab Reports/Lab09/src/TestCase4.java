/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

 package phase1Base;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1Base.Common.*;

public class TestCase4 {
    
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
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Receiver (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Receiver (Random Data) "));
        }
        User bobReceiver = createReceiver("Bob");
        getRSAKeys(bobReceiver);
        System.out.println("==> Receiver's Status" + " | " + bobReceiver.toString() + "\n");

        //Sender Encrypts message
        System.out.println(caseSeperator("*", "CASE #4: Using public-key cryptography, suppose Sender wants to send a secret message to Receiver, and Receiver wants to be sure that the message was indeed sent by the Sender."));
        System.out.println(caseSeperator("+", "Sender Operations"));
        BigInteger cipher = senderCase4(amySender, bobReceiver);
        System.out.println("==> Sender sends out cipher = | " + cipher + "\n");
        
        //Receiver Decrypts message
        System.out.println(caseSeperator("+", "Receiver Operations"));
        BigInteger msg = receiverCase4(bobReceiver, amySender, cipher);
        System.out.println("==> Receiver receives and decrypt msg = | " + msg + "\n");

    }

    public static User createSender(String name, boolean fixedData) {
        step++;
        System.out.println("\n--- Step #" + step + ": START - Sender generates\t" + padding);
        User sender = new User("Amy", Common.Role.SENDER, fixedData);
        System.out.println(indent1 + sender.toString());
        sender.printDetails();
        System.out.println("--- Step #" + step + ": END of this Step \t\t" + padding + "\n");
        return sender;
    }

    public static User createReceiver(String name) {
        step = 1;
        System.out.println("\n--- Step #" + step + ": START - Receiver generates\t" + padding);
        User receiver = new User("Bob", Common.Role.RECEIVER);
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

    public static BigInteger senderCase4(User sender, User receiver) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Sender should encrypt the message with its private key, encrypt the result with Receiver’s public key, and then send the encrypted message to Receiver.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should Pb+(Pa-(Msg))-> cipher");
        return senderOperationsCase4(sender, receiver);
    }

    public static BigInteger receiverCase4(User receiver, User sender, BigInteger cipher) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives cipher = " + cipher);
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Receiver should decrypt the cipher with its private key then with sender's public key");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should Pa+(Pb-(cipher)) =  Msg");
        return receiverOperationsCase4(receiver, sender, cipher);
    }

    private static BigInteger senderOperationsCase4(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase4 ----------------");
        System.out.println(indent2 + "senderPrivateKeyN = " + sender.getPrivateKey()[0]);
        System.out.println(indent2 + "senderPrivateKeyD = " + sender.getPrivateKey()[1]);
        System.out.println(indent2 + "receiverPubKeyN = " + receiver.getPubKey()[0]);
        System.out.println(indent2 + "receiverPubKeyE = " + receiver.getPubKey()[1]);
        BigInteger cipherA = Cryptography.rsaEncrypt(sender.getPrivateKey(), sender.getMsg());
        BigInteger cipherB = Cryptography.rsaEncrypt(receiver.getPubKey(), cipherA);
        System.out.println(indent2 + "Pa-(Msg) = " + cipherA);
        System.out.println(indent2 + "Pb+(Pa-(Msg)) = " + cipherB);
        System.out.println(indent2 + "------------------End | senderOperationsCase4 ----------------");
        return cipherB;

    }
    
    private static BigInteger receiverOperationsCase4(User receiver, User sender, BigInteger cipher) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase4 ----------------");
        System.out.println(indent2 + "receiverPrivateKeyN = " + receiver.getPrivateKey()[0]);
        System.out.println(indent2 + "receiverPrivateKeyD = " + receiver.getPrivateKey()[1]);
        System.out.println(indent2 + "senderPubKeyN = " + sender.getPubKey()[0]);
        System.out.println(indent2 + "senderPubKeyE = " + sender.getPubKey()[1]);
        BigInteger halfMsg = Cryptography.rsaDecrypt(receiver.getPrivateKey(), cipher);
        BigInteger msg = Cryptography.rsaDecrypt(sender.getPubKey(), halfMsg);
        receiver.setMsg(msg);
        System.out.println(indent2 + "decryptedMsg = " + msg);
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "------------------ End | receiverOperationsCase4 ----------------\n");
        return msg;
    }
}