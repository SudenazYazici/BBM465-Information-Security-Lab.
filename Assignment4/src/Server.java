import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import java.io.FileWriter;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class Server {

    private String id;
    private KeyPair keyPair;
    private Ticket serverTicket;

    public Server(String id, KDC kdc) throws Exception {
        this.id = id;

        // read server keys from CSV
        PrivateKey serverPriv = kdc.getServersPrivateKey(id);
        String[] row = kdc.findRowByServerId(id);
        if (row == null) {
            throw new Exception("Server row not found in CSV for id=" + id);
        }
        byte[] pubBytes = Base64.getDecoder().decode(row[7].trim());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey serverPub = kf.generatePublic(new X509EncodedKeySpec(pubBytes));

        this.keyPair = new KeyPair(serverPub, serverPriv);
    }

    public String getId() { return id; }
    public PublicKey getPublicKey() { return keyPair.getPublic(); }
    public PrivateKey getPrivateKey() { return keyPair.getPrivate(); }
    public Ticket getServerTicket() { return serverTicket; }

    public void setServerTicket(Ticket ticket) {
        this.serverTicket = ticket;
    }

    public SecretKey decryptServerTicket(KDC kdc) throws Exception {
        if (serverTicket == null) {
            throw new IllegalStateException("Server ticket is null.");
        }
        return kdc.decryptSessionKey(
                serverTicket.getEncryptedSessionKey(),
                this.getPrivateKey()
        );
    }

    public String communicateWithClient(String clientPlainSessionKeyBase64,
                                        String encryptedMessage,
                                        KDC kdc) throws Exception {
        try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
            logWriter.append("\n[Server communicateWithClient]\n")
                     .append("Client's plaintext session key (Base64): ")
                     .append(clientPlainSessionKeyBase64).append("\n");
        }

        SecretKey serverSessionKey = decryptServerTicket(kdc);

        byte[] clientKeyBytes = Base64.getDecoder().decode(clientPlainSessionKeyBase64);
        SecretKey clientSessionKey = new javax.crypto.spec.SecretKeySpec(clientKeyBytes, "AES");

        if (!Arrays.equals(serverSessionKey.getEncoded(), clientSessionKey.getEncoded())) {
            try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                logWriter.append("[Server] Session keys do not match. Communication failed.\n");
            }
            return "Error: Session keys do not match. Communication failed.";
        }

        if (encryptedMessage == null || encryptedMessage.isEmpty()) {
            return "[Server] No encrypted message received, but session keys match => communication established.";
        }

        // decrypt
        String result = decryptMessage(encryptedMessage, serverSessionKey);
        try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
            logWriter.append("[Server] Session keys matched. Decrypted message: ")
                     .append(result).append("\n");
        }
        return result;
    }

    public String decryptMessage(String encryptedMessage, SecretKey sessionKey) throws Exception {
        byte[] data = Base64.getDecoder().decode(encryptedMessage);

        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] ivBytes = new byte[16];
        bb.get(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] encData = new byte[bb.remaining()];
        bb.get(encData);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, sessionKey, iv);
        byte[] dec = c.doFinal(encData);
        return new String(dec);
    }

    public String encryptMessage(String message, SecretKey sessionKey) throws Exception {
        SecureRandom rand = new SecureRandom();
        byte[] ivBytes = new byte[16];
        rand.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, sessionKey, iv);
        byte[] enc = c.doFinal(message.getBytes());

        ByteBuffer bb = ByteBuffer.allocate(ivBytes.length + enc.length);
        bb.put(ivBytes);
        bb.put(enc);

        return Base64.getEncoder().encodeToString(bb.array());
    }
}
