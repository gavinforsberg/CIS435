/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

 
package phase1Base;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1Base.Common.*;

/**
 *
 * @author yun
 */
public class TestCase2 {
    
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
        System.out.println(caseSeperator("*", "CASE #0_2 | Initialize Receiver (Random Data) "));
        User bobReceiver = createReceiver("Bob");
        getRSAKeys(bobReceiver);
        System.out.println("==> Receiver's Status" + " | " + bobReceiver.toString() + "\n");

        //Sender Encrypts message
        System.out.println(caseSeperator("*", "CASE #2: Using public-key cryptography, suppose Sender wants to send a message to Receiver and Receiver wants to be sure that the message was indeed sent by the Sender."));
        System.out.println(caseSeperator("+", "Sender Operations"));
        BigInteger cipher = senderCase2(amySender, bobReceiver);
        System.out.println("==> Sender sends out cipher = | " + cipher + "\n");
        
        //Receiver Decrypts message
        System.out.println(caseSeperator("+", "Receiver Operations"));
        BigInteger msg = receiverCase2(bobReceiver, amySender, cipher);
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

    public static BigInteger senderCase2(User sender, User receiver) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Sender should encrypt the message with their private key and send the encrypted message");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should Pa-(Msg)-> cipher");
        return senderOperationsCase2(sender, receiver);
    }

    public static BigInteger receiverCase2(User receiver, User sender, BigInteger cipher) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives cipher = " + cipher);
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Receiver should decrypt the cipher with the sender's public key");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should Pa+(cipher) =  Msg");
        return receiverOperationsCase2(receiver, sender, cipher);
    }

    private static BigInteger senderOperationsCase2(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase2 ----------------");
        System.out.println(indent2 + "receiverPrivateKeyN = " + sender.getPrivateKey()[0]);
        System.out.println(indent2 + "receiverPrivateKeyD = " + sender.getPrivateKey()[1]);
        BigInteger cipher = Cryptography.rsaEncrypt(sender.getPrivateKey(), sender.getMsg());
        System.out.println(indent2 + "cipher = " + cipher);
        System.out.println(indent2 + "------------------End | senderOperationsCase2 ----------------");
        return cipher;

    }

    private static BigInteger receiverOperationsCase2(User receiver, User sender, BigInteger cipher) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase2 ----------------");
        BigInteger msg = Cryptography.rsaDecrypt(sender.getPubKey(), cipher);
        receiver.setMsg(msg);
        System.out.println(indent2 + "decryptedMsg = " + msg);
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "------------------ End | receiverOperationsCase2 ----------------\n");
        return msg;
    }

}