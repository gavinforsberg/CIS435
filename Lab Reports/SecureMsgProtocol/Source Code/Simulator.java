package phase2;

import phase2.Common.Role;
import java.math.BigInteger;

public class Simulator {

    public static User sender;
    public static User receiver;
    public static SecMsgProtocol secMsgProtocol = new SecMsgProtocol();
    public static Network network = new Network();

    public static void main(String[] args) {
        System.out.println("\n\nInitializing SENDER and RECEIVER\n");
        
        sender = new User("Amy", Role.SENDER);
        getRSAKeys(sender);
        System.out.println("\tInitialized SENDER: |" + sender.toString() + "\n");
        
        receiver = new User("Bob", Role.RECEIVER);
        getRSAKeys(receiver);
        System.out.println("\tInitialized RECEIVER: |" + receiver.toString() + "\n");


        // case1();
        // case2();
        // case3();
        case4();
    }

    public static void case1() {
        System.out.println("CASE 1: Fixed Data and NO Hack");
        
        //Populate fixed data
        sender.setMsg(BigInteger.valueOf(17));
        sender.setKs(BigInteger.valueOf(5));
        sender.setHashBase(BigInteger.valueOf(13));
        System.out.println("\tSender status: |" + sender.toString());

        // receiver.setKs(BigInteger.valueOf(5));
        receiver.setHashBase(BigInteger.valueOf(13));
        System.out.println("\tReceiver status: |" + receiver.toString());

        logOperationStatus(Side.SENDER, Direction.START);
        Packet sentPacket = secMsgProtocol.send(sender, receiver);
        logOperationStatus(Side.SENDER, Direction.END);

        //Network
        System.out.println("\n==> Sender sends packet to Network:\n" + sentPacket.toString());
        network.pkInFromSender(sentPacket);
        Packet receivedPacket = network.pkOutToReceiver();

        logOperationStatus(Side.RECEIVER, Direction.START);
        secMsgProtocol.receive(receivedPacket, receiver, sender);
        logOperationStatus(Side.RECEIVER, Direction.END);

    }

    public static void case2() {
        System.out.println("CASE 2: Fixed Data WITH Hack");
        
        //Populate fixed data
        sender.setMsg(BigInteger.valueOf(17));
        sender.setKs(BigInteger.valueOf(5));
        sender.setHashBase(BigInteger.valueOf(13));
        System.out.println("\tSender status: |" + sender.toString());

        // receiver.setKs(BigInteger.valueOf(5));
        receiver.setHashBase(BigInteger.valueOf(13));
        System.out.println("\tReceiver status: |" + receiver.toString());

        logOperationStatus(Side.SENDER, Direction.START);
        Packet sentPacket = secMsgProtocol.send(sender, receiver);
        logOperationStatus(Side.SENDER, Direction.END);

        //Network
        System.out.println("\n==> Sender sends packet to Network:\n" + sentPacket.toString());
        network.pkInFromSender(sentPacket);
        network.pkGetHacked();
        Packet receivedPacket = network.pkOutToReceiver();

        logOperationStatus(Side.RECEIVER, Direction.START);
        secMsgProtocol.receive(receivedPacket, receiver, sender);
        logOperationStatus(Side.RECEIVER, Direction.END);
    }

    public static void case3() {
        System.out.println("CASE 3: Random Data and NO Hack");

        //Populate random data
        BigInteger msg = BigInteger.valueOf((int)(Math.random() * 1000));
        BigInteger ks = BigInteger.valueOf((int)(Math.random() * 1000));
        BigInteger hashBase = BigInteger.valueOf((int)(Math.random() * 1000));

        sender.setMsg(msg);
        sender.setKs(ks);
        sender.setHashBase(hashBase);
        System.out.println("\tSender status: |" + sender.toString());
        
        // receiver.setKs(ks);
        receiver.setHashBase(hashBase);
        System.out.println("\tReceiver status: |" + receiver.toString());

        logOperationStatus(Side.SENDER, Direction.START);
        Packet sentPacket = secMsgProtocol.send(sender, receiver);
        logOperationStatus(Side.SENDER, Direction.END);

        //Network
        System.out.println("\n==> Sender sends packet to Network:\n" + sentPacket.toString());
        network.pkInFromSender(sentPacket);
        Packet receivedPacket = network.pkOutToReceiver();

        logOperationStatus(Side.RECEIVER, Direction.START);
        secMsgProtocol.receive(receivedPacket, receiver, sender);
        logOperationStatus(Side.RECEIVER, Direction.END);
    }

    public static void case4() {
        System.out.println("CASE 4: Random Data WITH Hack");
        
        //Populate random data
        BigInteger msg = BigInteger.valueOf((int)(Math.random() * 1000));
        BigInteger ks = BigInteger.valueOf((int)(Math.random() * 1000));
        BigInteger hashBase = BigInteger.valueOf((int)(Math.random() * 1000));

        sender.setMsg(msg);
        sender.setKs(ks);
        sender.setHashBase(hashBase);
        System.out.println("\tSender status: |" + sender.toString());
        
        // receiver.setKs(ks);
        receiver.setHashBase(hashBase);
        System.out.println("\tReceiver status: |" + receiver.toString());

        logOperationStatus(Side.SENDER, Direction.START);
        Packet sentPacket = secMsgProtocol.send(sender, receiver);
        logOperationStatus(Side.SENDER, Direction.END);

        //Network
        System.out.println("\n==> Sender sends packet to Network:\n" + sentPacket.toString());
        network.pkInFromSender(sentPacket);
        network.pkGetHacked();
        Packet receivedPacket = network.pkOutToReceiver();

        logOperationStatus(Side.RECEIVER, Direction.START);
        secMsgProtocol.receive(receivedPacket, receiver, sender);
        logOperationStatus(Side.RECEIVER, Direction.END);
    }

    public static void getRSAKeys(User user) {
        Cryptography crypto = new Cryptography();
        user.setPubKey(crypto.getPublicKey());
        user.setPrivateKey(crypto.getPrivateKey());
    }

    public static enum Side {
        SENDER, RECEIVER
    }

    public static enum Direction {
        START, END
    }

    public static void logOperationStatus(Side side, Direction start) {
        
        String party = "";
        String direction = "";
        if (side == Side.SENDER) {
            party = "Sender";
        } else {
            party = "Receiver";
        }
        if (start == Direction.START) {
            direction = "Start";
        } else {
            direction = "End";
        }

        System.out.println("++++++++++++++++++++++++++++++++++++++++\n");
        System.out.println(direction + " of " + party + " Operations");
        System.out.println("\n++++++++++++++++++++++++++++++++++++++++");
    }
}
