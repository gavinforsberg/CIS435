/**
 *
 * @author Georges Samaha, Gavin Forsberg, Jacob Gnatz
 */

 package phase1Base;

import java.math.BigInteger;
import java.util.Arrays;
import static phase1Base.Common.*;

public class TestCase6 {
           
    public static void test()
    {
        //Initialize Sender (Amy)
        boolean fixedData = false;
        if (fixedData) {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Sender (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Sender (Random Data) "));
        }
        User amySender = createSender("Amy", fixedData);
        BigInteger ks = BigInteger.valueOf((int) (Math.random() * 1000)); 
        amySender.setKs(ks);
        amySender.setHashBase(BigInteger.valueOf(13));
        // getRSAKeys(amySender);
        System.out.println("==> Sender's Status" + " | " + amySender.toString() + "\n");

        //Initialize Receiver (Bob)
        if (fixedData) {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Receiver (Fixed Data) "));
        } else {
            System.out.println(caseSeperator("*", "CASE #0_1 | Initialize Receiver (Random Data) "));
        }
        User bobReceiver = createReceiver("Bob");
        bobReceiver.setKs(ks);
        bobReceiver.setHashBase(BigInteger.valueOf(13));
        // getRSAKeys(bobReceiver);
        System.out.println("==> Receiver's Status" + " | " + bobReceiver.toString() + "\n");

        //Sender Encrypts message
        System.out.println(caseSeperator("*", "CASE #6: Suppose Sender wants to send Receiver a message with  MAC"));
        System.out.println(caseSeperator("+", "Sender Operations"));
        BigInteger[] cipher = senderCase6(amySender, bobReceiver);
        System.out.println("==> Sender sends out cipher = | " + Arrays.toString(cipher) + "\n");
        
        //Receiver Decrypts message
        System.out.println(caseSeperator("+", "Receiver Operations"));
        receiverCase6(bobReceiver, amySender, cipher);
        // System.out.println("==> Receiver receives and decrypt msg = | " + msg + "\n");
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

    public static BigInteger[] senderCase6(User sender, User receiver) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + sender.toString());
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Sender should apply a hash function to the message concatenated with Ks then attach the hash to the message and send it.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Sender should [Msg, H(Msg + Ks)]-> cipher");
        return senderOperationsCase6(sender, receiver);
    }
    
    public static void receiverCase6(User receiver, User sender, BigInteger[] payload) {
        int subStep = 0;
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Initial case");
        System.out.println(indent2 + receiver.toString());
        System.out.println(indent2 + "Receiver receives payload = " + Arrays.toString(payload));
        System.out.println(indent2 + "Msg received = " + payload[0]);
        subStep++;
        System.out.println("\n" + indent1 + "Sub-Step #" + subStep + ": Receiver should re-hash the message with the Ks they have and compare that to the hash received.");
        System.out.println(indent1 + "Sub-Step #" + subStep + ": Receiver should H(Msg + Ks) ==  H2(Msg + Ks)");
        receiverOperationsCase6(receiver, sender, payload);
    }


    private static BigInteger[] senderOperationsCase6(User sender, User receiver) {

        System.out.println("\n" + indent2 + "------------------Start | senderOperationsCase6 ----------------");
        System.out.println(indent2 + "Symmetric Key = " + sender.getKs());
        System.out.println(indent2 + "senderHashBase = " + receiver.getHashBase());

        BigInteger msg = sender.getMsg();
        String strMsg = msg.toString();
        String strKey = sender.getKs().toString();
        String concat = strMsg + strKey;

        BigInteger concatBI = BigInteger.valueOf(Integer.parseInt(concat));
        
        BigInteger hash = Cryptography.hash(concatBI, sender.getHashBase());
        
        BigInteger[] payload = new BigInteger[2];
        payload[0] = msg;
        payload[1] = hash;

        return payload;
    }

    private static void receiverOperationsCase6(User receiver, User sender, BigInteger[] payload) {

        System.out.println("\n" + indent2 + "------------------Start | receiverOperationsCase6 ----------------");
        System.out.println(indent2 + "Symmetric Key = " + receiver.getKs());
        System.out.println(indent2 + "senderHashBase = " + receiver.getHashBase());

        BigInteger recHash = payload[1];

        BigInteger msg = payload[0];
        String strMsg = msg.toString();
        String strKey = receiver.getKs().toString();
        String concat = strMsg + strKey;
        // System.out.println("RESULT: "+concat);
        BigInteger concatBI = BigInteger.valueOf(Integer.parseInt(concat));
        
        BigInteger hash = Cryptography.hash(concatBI, receiver.getHashBase());

        if (recHash.equals(hash)) {
            System.out.println(indent2 + "Hashes match. Message verified. Message is: " + payload[0]);
            receiver.setMsg(payload[0]);
        } else {
            System.out.println(indent2 + "Hashes don't match. Message could not be verified."); 
		}
    }
}