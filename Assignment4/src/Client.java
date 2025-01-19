import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

public class Client {

    private String id;
    private String password;
    private Ticket clientTicket;

    public Client(String id, String password) {
        this.id = id;
        this.password = password;
    }

    public String getId() { return id; }
    public String getPassword() { return password; }
    public Ticket getClientTicket() { return clientTicket; }

    public void setClientTicket(Ticket t) {
        this.clientTicket = t;
    }

    public boolean isTicketExpired() {
        return clientTicket != null && clientTicket.getExpirationTime().isBefore(Instant.now());
    }

    public String encryptMessage(String message, SecretKey sessionKey) throws Exception {
        SecureRandom rand = new SecureRandom();
        byte[] ivBytes = new byte[16];
        rand.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
        byte[] encData = c.doFinal(message.getBytes());

        ByteBuffer bb = ByteBuffer.allocate(ivBytes.length + encData.length);
        bb.put(ivBytes);
        bb.put(encData);
        byte[] combined = bb.array();

        try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
            logWriter.append("\n[Client encryptMessage]\n")
                     .append("Message: ").append(message).append("\n")
                     .append("IV (Base64): ").append(Base64.getEncoder().encodeToString(ivBytes)).append("\n")
                     .append("Encrypted (Base64): ").append(Base64.getEncoder().encodeToString(combined)).append("\n");
        }
        return Base64.getEncoder().encodeToString(combined);
    }
}
