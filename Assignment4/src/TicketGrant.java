import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

public class TicketGrant extends KDC {

    public TicketGrant() {
        super(); // call KDC constructor
    }

    /**
     * Create tickets for client and server
     */
    public Ticket[] createTicketsFor(String clientId, String serverId, String[] row) throws Exception {
        // row => "Client, c1, password, cPub, cPriv, Server, s1, sPub, sPriv"
        // decode public keys
        byte[] clientPubBytes = Base64.getDecoder().decode(row[3]);
        byte[] serverPubBytes = Base64.getDecoder().decode(row[7]);

        java.security.PublicKey clientPub = getPublicKey(clientPubBytes);
        java.security.PublicKey serverPub = getPublicKey(serverPubBytes);

        // 1) generate session key
        SecretKey sessionKey = generateSessionKey();

        // 2) encrypt session key with client & server pubkeys
        String encForClient = encryptWithPublicKey(sessionKey.getEncoded(), clientPub);
        String encForServer = encryptWithPublicKey(sessionKey.getEncoded(), serverPub);

        Instant exp = Instant.now().plus(5, ChronoUnit.MINUTES);

        Ticket clientTicket = new Ticket(clientId, serverId, encForClient, exp);
        Ticket serverTicket = new Ticket(clientId, serverId, encForServer, exp);

        // log
        try (java.io.FileWriter logWriter = new java.io.FileWriter(LOG_FILE, true)) {
            logWriter.append("\n[TICKETGRANT: CREATE TICKETS]\n")
                     .append("sessionKey (Base64): ")
                     .append(javax.xml.bind.DatatypeConverter.printBase64Binary(sessionKey.getEncoded()))
                     .append("\nclientTicket: ").append(clientTicket.toString())
                     .append("\nserverTicket: ").append(serverTicket.toString())
                     .append("\n");
        }

        return new Ticket[]{ clientTicket, serverTicket };
    }

    protected PublicKey getPublicKey(byte[] pubBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new X509EncodedKeySpec(pubBytes));
    }

    /**
     * AES 128-bit
     */
    public SecretKey generateSessionKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg.generateKey();
    }

    /**
     * RSA encrypt
     */
    public String encryptWithPublicKey(byte[] data, PublicKey pub) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data));
    }
}
