package phase2;

import java.math.BigInteger;

public class SecMsgProtocol {
    
    public Packet send(User sender, User receiver) {
        
        printStatus();

        // Operations
        Packet packetOut = new Packet();

        //Step 1: get msg
        System.out.println("\n---Step 1: Sender generates message: m = " + sender.getMsg());

        //Step 2: hash msg
        BigInteger hash = Cryptography.hash(sender.getMsg(), sender.getHashBase());
        System.out.println("\n---Step 2: Sender hashes message: H(m) = " + hash);
        
        //Step 3: encrypt hashed msg --> generate digital sig
        System.out.println("\n---Step 3: Sign H(m) with sender's private key and generate digital signature:");
        BigInteger digSig = Cryptography.rsaEncrypt(sender.getPrivateKey(), hash);
        System.out.println("Ka-(H(m)) = " + digSig);
        
        //Step 4: generate ks
        System.out.println("\n---Step 4: Generate a session key: Ks = " + sender.getKs());

        //Step 5: encrypt ks w/ receiver public key
        System.out.println("\n---Step 5: encrypt Ks with receiver's public key using RSA algorithm:");
        BigInteger encKs = Cryptography.rsaEncrypt(receiver.getPubKey(), sender.getKs());
        System.out.println("Kb+(Ks) = " + encKs);
        packetOut.setEncKs(encKs);
        System.out.println(">>>Set packet encryptedKs to " + packetOut.getEncKs());
        
        //Step 6: encrypt msg w/ ks
        System.out.println("\n---Step 6: encrypt message m with session key and symmetric algorithm:");
        BigInteger encMsg = Cryptography.shift(sender.getMsg(), sender.getKs(), true);
        System.out.println("Ks(m) = " + encMsg);
        packetOut.setCipher(encMsg);
        System.out.println(">>>Set packet cipher to " + packetOut.getCipher());

        //Step 7: encrypt dig sig 
        System.out.println("\n---Step 7: encrypt sender's digital signature Ka-(H(m)) using session key (ks) and symmetric algorithm");
        BigInteger encDigSig = Cryptography.shift(digSig, sender.getKs(), true);
        System.out.println("Ks(Ka-(H(m))) = " + encDigSig);
        packetOut.setEncDigSig(encDigSig);
        System.out.println(">>>Set packet encrypted digital signature to " + encDigSig);

        //Step 8: create packet w/ all three fields (ks, msg, dig sig)
        System.out.println("\n---Step 8: the packet to be sent on to Internet is:");
        System.out.println(packetOut.toString());

        //send packet to receiver w/ network/internet
        return packetOut;
    }

    public void receive(Packet packetIn, User receiver, User sender) {
        printStatus();

        //recieve
        System.out.println("\n--Step 1: Receive the packet from internet rcvPacket");

        //split fields
        System.out.println("\n--Step 2: Split the Packet");
        BigInteger encMsg = packetIn.getCipher();
        BigInteger encKs = packetIn.getEncKs();
        BigInteger encDigSig = packetIn.getEncDigSig();
        System.out.println("pk.cipher 'Ks(m)' = " + encMsg);
        System.out.println("pk.digitalSignature 'Ks(Ka-(H(m)))' = " + encDigSig);
        System.out.println("pk.encryptedKs 'Kb(Ks)' = " + encKs);

        //decrypt ks w private key
        System.out.println("\n---Step 3: Decrypt Kb+(Ks) with Receiver's private key 'Kb-'");
        BigInteger decKs = Cryptography.rsaDecrypt(receiver.getPrivateKey(), encKs);
        System.out.println("Receiver: the encryptedKs 'Kb+(Ks)' is: " + encKs);
        System.out.println("After decrypting with receiver's privateky 'Kb-', get Ks = " + decKs);

        //decrypt message with ks
        System.out.println("\n--Step 4: decrypt pk.cipher, i.e., 'Ks(m)' using Ks which is gotten from step 3: " + encMsg);
        BigInteger decMsg = Cryptography.shift(encMsg, decKs, false);
        System.out.println("After decryption receiver gets messgae 'm' = " + decMsg);

        //decrypt signature with ks
        System.out.println("\n--Step 5: Decrypt Ks(Ka-(H(m)))' with 'Ks' gotten from step 3, Ks(Ka-(H(m))) = " + encDigSig);
        BigInteger ksDigSig = Cryptography.shift(encDigSig, decKs, false);
        System.out.println("and get the digital signature 'Ka-(H(m))' = " + ksDigSig);
        
        //decrypt signature with sender public key
        System.out.println("\n--Step 6: Decrypt 'Ka-(H(m))' from sender's public key 'Ka+()'");
        BigInteger senderDigSig = Cryptography.rsaDecrypt(sender.getPubKey(), ksDigSig);
        System.out.println("The decrypted message digest 'H(m)' = Ka+(Ka-(H(m))) = " + senderDigSig);

        //hash message
        System.out.println("\n--Step 7: Hash message m from step 4 'm' = " + decMsg);
        BigInteger hash = Cryptography.hash(decMsg, receiver.getHashBase());
        System.out.println("The hash result H(m) = " + hash);

        //compare hashes, check if valid, accept and display or discard and issue error
        System.out.println("\n---Step 8: Compare results from step 6 and step 7, if they match then accept otherwise discards");
        if (hash.equals(senderDigSig)) {
            System.out.println("The packet has passed through the integrity checking and is accepted!");
            System.out.println("\n==> Receiver decrypts msg: " + decMsg + "\n");
        }
        else {
            System.out.println("\nThe packet did not pass the integrity checking and is not accepted!\n");
        }
    }


    public void printStatus() {
        System.out.println("----------------------------------------\n");
        System.out.println("| SecMsgProtocol (SSL) is READY to serve |");
        System.out.println("\n----------------------------------------");
    }
}