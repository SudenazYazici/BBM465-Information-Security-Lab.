import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.security.*;
import java.util.Base64;


public class KDC {

    protected static final String DATASET_FILE = "src/Dataset.csv";
    protected static final String LOG_FILE = "src/Log.txt";

    public KDC() { }

    // REGISTER
    public boolean registerClientAndServer(String clientId, String password, String serverId) throws Exception {
        if (clientServerPairExists(clientId, serverId)) {
            return false;
        }
        KeyPair clientKP = generateKeyPair();
        KeyPair serverKP = generateKeyPair();

        String clientPubB64 = Base64.getEncoder().encodeToString(clientKP.getPublic().getEncoded());
        String clientPrivB64 = Base64.getEncoder().encodeToString(clientKP.getPrivate().getEncoded());
        String serverPubB64 = Base64.getEncoder().encodeToString(serverKP.getPublic().getEncoded());
        String serverPrivB64 = Base64.getEncoder().encodeToString(serverKP.getPrivate().getEncoded());

        String csvLine = String.join(",",
                "Client", clientId, password,
                clientPubB64, clientPrivB64,
                "Server", serverId, serverPubB64, serverPrivB64
        );
        try (FileWriter fw = new FileWriter(DATASET_FILE, true)) {
            fw.append(csvLine).append("\n");
        }
        try (FileWriter logWriter = new FileWriter(LOG_FILE, true)) {
            logWriter.append("\n[KDC REGISTER]\n")
                     .append("Client ").append(clientId).append(" and Server ")
                     .append(serverId).append(" keys created.\n");
        }
        return true;
    }

    // LOGIN
    public Ticket[] loginAndGrantTickets(String clientId, String password, String serverId) throws Exception {
        String[] row = getClientServerRow(clientId, serverId);
        if (row == null) {
            throw new Exception("Client–Server pair not found in CSV.");
        }
        if (!password.equals(row[2])) {
            throw new Exception("Wrong password for client: " + clientId);
        }

        // if success
        // Now we create a TicketGrant subclass (TGS)
        TicketGrant tgs = new TicketGrant();  // <-- Subclass
        return tgs.createTicketsFor(clientId, serverId, row);
    }

    // DECRYPT
    public SecretKey decryptSessionKey(String encryptedSessionKey, PrivateKey privKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] dec = cipher.doFinal(Base64.getDecoder().decode(encryptedSessionKey));
        return new SecretKeySpec(dec, "AES");
    }

    // GET CLIENT/SERVER PRIVATE KEY
    public PrivateKey getClientsPrivateKey(String clientId) throws Exception {
        String[] row = findRowByClientId(clientId);
        if (row == null) {
            throw new Exception("No row found for clientId=" + clientId);
        }
        byte[] privBytes = Base64.getDecoder().decode(row[4]);
        return getPrivateKeyFromBytes(privBytes);
    }

    public PrivateKey getServersPrivateKey(String serverId) throws Exception {
        String[] row = findRowByServerId(serverId);
        if (row == null) {
            throw new Exception("No row found for serverId=" + serverId);
        }
        byte[] privBytes = Base64.getDecoder().decode(row[8]);
        return getPrivateKeyFromBytes(privBytes);
    }

    // HELPER
    protected KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    protected PrivateKey getPrivateKeyFromBytes(byte[] privBytes) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(privBytes));
    }

    // CSV read
    protected String[] getClientServerRow(String clientId, String serverId) {
        try (BufferedReader br = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] cols = line.split(",");
                if (cols.length == 9) {
                    if (clientId.equals(cols[1].trim()) && serverId.equals(cols[6].trim())) {
                        return cols;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    protected String[] findRowByClientId(String clientId) {
        try (BufferedReader br = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] cols = line.split(",");
                if (cols.length == 9) {
                    if ("Client".equals(cols[0]) && clientId.equals(cols[1].trim())) {
                        return cols;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    protected String[] findRowByServerId(String serverId) {
        try (BufferedReader br = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] cols = line.split(",");
                if (cols.length == 9) {
                    if ("Server".equals(cols[5]) && serverId.equals(cols[6].trim())) {
                        return cols;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    protected boolean clientServerPairExists(String clientId, String serverId) {
        try (BufferedReader br = new BufferedReader(new FileReader(DATASET_FILE))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] cols = line.split(",");
                if (cols.length == 9) {
                    if (clientId.equals(cols[1].trim()) && serverId.equals(cols[6].trim())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return false;
    }
}
