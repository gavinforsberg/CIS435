/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

package phase1Base;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1Base.Common.*;

public class TestCase3 {

    public static void test() {

        //Initialize Sender (Amy)
        boolean fixedData = false;
        if (fixedData) {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Sender (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Sender (Random Data) "));
        }
        BigInteger ks = BigInteger.valueOf((int) (Math.random() * 1000));

        User amySender = createSender("Amy", fixedData);
        amySender.setKs(ks);
        amySender.setHashBase(BigInteger.valueOf(13));
        System.out.println("==> Sender's Status" + " | " + amySender.toString() + "\n");

        //Initialize Receiver (Bob)
        if (fixedData) {
            System.out.println(caseSeperator("*", "CASE #0_2 | Initialize Receiver (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_2 | Initialize Receiver (Random Data) "));
        }
        User bobReceiver = createReceiver("Bob");
        bobReceiver.setKs(ks);
        bobReceiver.setHashBase(BigInteger.valueOf(13));
        System.out.println("==> Receiver's Status" + " | " + bobReceiver.toString() + "\n");

        //Sender Encrypts message
        System.out.println(caseSeperator("*", "CASE #3: Using symmetric-key cryptography, suppose Sender wants to send a secret message to the Receiver, and Receiver wants to be sure that the message was indeed the original one."));
        System.out.println(caseSeperator("+", "Sender Operations"));
        BigInteger[] payload = senderCase3(amySender, bobReceiver);
        System.out.println("==> Sender sends out : | " + Arrays.toString(payload) + "\n");
        
        //Receiver Decrypts message
        System.out.println(caseSeperator("+", "Receiver Operations"));
        /*BigInteger msg = */receiverCase3(bobReceiver, amySender, payload);
        // System.out.println("==> Receiver receives and verifies msg = | " + msg + "\n");

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

    public static BigInteger[] senderCase3(User sender, User receiver) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Sender should encrypt the message with Ks then apply the hash, concatenate this hash to the encrypted message and send it.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should [Ks(Msg), H(Ks(Msg))] -> payload");
        return senderOperationsCase3(sender, receiver);
    }

    public static void receiverCase3(User receiver, User sender, BigInteger[] payload) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives payload = " + Arrays.toString(payload));
        System.out.println(indent2 + "Msg received = " + payload[0]);
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Receiver should hash the encrypted message and compare that hash to the hash from the payload, if equal decrypt the encrypted message using Ks.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should H2(Ks(Msg)) ==  H(Ks(Msg)) then Ks(Ks(Msg)).");
        receiverOperationsCase3(receiver, sender, payload);
    }

    private static BigInteger[] senderOperationsCase3(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase3 ----------------");
        System.out.println(indent2 + "senderHashBase = " + sender.getHashBase());
        System.out.println(indent2 + "senderKs = " + sender.getKs());
        

        BigInteger msg = sender.getMsg();
        BigInteger encMsg = Cryptography.shift(msg, sender.getKs(), true);
        BigInteger hash = Cryptography.hash(encMsg, sender.getHashBase());
        

        //BigInteger hash = Cryptography.hash(msg, sender.getHashBase());
        BigInteger[] payload = new BigInteger[2];
        payload[0] = encMsg;
        payload[1] = hash;

        System.out.println(indent2 + "Msg = " + msg);
        System.out.println(indent2 + "H(Msg) = " + hash);
        System.out.println(indent2 + "Payload = " + Arrays.toString(payload));
        System.out.println(indent2 + "------------------End | senderOperationsCase3 ----------------");
        return payload;

    }

    private static void receiverOperationsCase3(User receiver, User sender, BigInteger[] payload) {

        System.out.println("\n" + indent2 + "------------------ Start | receiverOperationsCase3 ----------------");
        System.out.println(indent2 + "receiverHashBase = " + receiver.getHashBase());
        System.out.println(indent2 + "receiverKs = " + receiver.getKs());

        BigInteger hash1 = payload[1];
        BigInteger hash2 = Cryptography.hash(payload[0], receiver.getHashBase());

        System.out.println(indent2 + "Hash from Ks(payload) = " + hash1);
        System.out.println(indent2 + "H2(Msg) = " + hash2);

        if (hash1.equals(hash2)) {
            BigInteger msg = Cryptography.shift(payload[0], receiver.getKs(), false);
            System.out.println(indent2 + "Hashes match. Message verified. Message is: " + msg);
            receiver.setMsg(msg);
        } else {
            System.out.println(indent2 + "Hashes don't match. Message could not be verified.");
        }
        
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "------------------ End | receiverOperationsCase3 ----------------\n");
    }
}