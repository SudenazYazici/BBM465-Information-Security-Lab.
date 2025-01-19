import java.time.Instant;

public class Ticket {
    private String clientId;
    private String serverId;
    private String encryptedSessionKey;
    private Instant expirationTime;

    public Ticket(String clientId, String serverId, String encryptedSessionKey, Instant expirationTime) {
        this.clientId = clientId;
        this.serverId = serverId;
        this.encryptedSessionKey = encryptedSessionKey;
        this.expirationTime = expirationTime;
    }

    public String getClientId() { return clientId; }
    public String getServerId() { return serverId; }
    public String getEncryptedSessionKey() { return encryptedSessionKey; }
    public Instant getExpirationTime() { return expirationTime; }

    public boolean isExpired() {
        return Instant.now().isAfter(expirationTime);
    }

    @Override
    public String toString() {
        return "Ticket{" +
                "clientId='" + clientId + '\'' +
                ", serverId='" + serverId + '\'' +
                ", encryptedSessionKey='" + encryptedSessionKey + '\'' +
                ", expirationTime=" + expirationTime +
                '}';
    }
}
