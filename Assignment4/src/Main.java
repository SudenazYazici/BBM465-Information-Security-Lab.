import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

import javax.crypto.SecretKey;
import java.io.FileWriter;

public class Main extends Application {

    
    private KDC kdc = new KDC();

    private Client currentClient;
    private Server currentServer;

    @Override
    public void start(Stage primaryStage) throws Exception {

        Label clientLabel = new Label("Client ID:");
        TextField clientField = new TextField();
        Label passwordLabel = new Label("Password:");
        PasswordField passwordField = new PasswordField();
        Label serverLabel = new Label("Server ID:");
        TextField serverField = new TextField();
        Label messageLabel = new Label("Message:");
        TextField messageField = new TextField();
        TextArea logArea = new TextArea();
        logArea.setEditable(false);

        Button registerButton = new Button("Register");
        Button loginButton = new Button("LogIn");
        Button communicateButton = new Button("Communicate with Server");

        // ------------------------------------------------------------
        // REGISTER
        // ------------------------------------------------------------
        registerButton.setOnAction(event -> {
            String clientId = clientField.getText().trim();
            String password = passwordField.getText().trim();
            String serverId = serverField.getText().trim();

            if (clientId.isEmpty() || password.isEmpty() || serverId.isEmpty()) {
                logArea.appendText("Error: fields cannot be empty.\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error: fields cannot be empty.\n");
                } catch (Exception ignore) {}
                return;
            }

            try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                logWriter.append("\n[REGISTER BUTTON CLICKED]\n")
                        .append("Client ").append(clientId)
                        .append(" with password ").append(password)
                        .append(" requesting registration with server ")
                        .append(serverId).append(".\n");

                boolean success = kdc.registerClientAndServer(clientId, password, serverId);
                if (success) {
                    logArea.appendText("Client registered successfully.\n");
                    logWriter.append("Client registered successfully.\n");
                } else {
                    logArea.appendText("Client–Server pair already exists. Registration aborted.\n");
                    logWriter.append("Client–Server pair already exists. Registration aborted.\n");
                }
            } catch (Exception e) {
                logArea.appendText("Error during registration: " + e.getMessage() + "\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error during registration: ").append(e.getMessage()).append("\n");
                } catch (Exception ignore) {}
            }
        });

        // ------------------------------------------------------------
        // LOGIN
        // ------------------------------------------------------------
        loginButton.setOnAction(event -> {
            String clientId = clientField.getText().trim();
            String password = passwordField.getText().trim();
            String serverId = serverField.getText().trim();

            if (clientId.isEmpty() || password.isEmpty() || serverId.isEmpty()) {
                logArea.appendText("Error: fields cannot be empty.\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error: fields cannot be empty.\n");
                } catch (Exception ignore) {}
                return;
            }

            try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                logWriter.append("\n[LOGIN BUTTON CLICKED]\n")
                        .append("Client ").append(clientId)
                        .append(" with password ").append(password)
                        .append(" is trying to authenticate with KDC for server ")
                        .append(serverId).append(".\n");

                logArea.appendText("Authenticating client...\n");
                logWriter.append("Authenticating client...\n");

                Ticket[] tickets = kdc.loginAndGrantTickets(clientId, password, serverId);
                if (tickets == null || tickets.length != 2) {
                    logArea.appendText("Error: Could not grant tickets.\n");
                    logWriter.append("Error: Could not grant tickets.\n");
                    return;
                }

                logArea.appendText("Authentication successful! Ticket granted.\n");
                logWriter.append("Authentication successful! Ticket granted.\n");

                Ticket clientTicket = tickets[0];
                Ticket serverTicket = tickets[1];

                currentClient = new Client(clientId, password);
                currentClient.setClientTicket(clientTicket);

                currentServer = new Server(serverId, kdc);
                currentServer.setServerTicket(serverTicket);
            } catch (Exception e) {
                logArea.appendText("Error during login: " + e.getMessage() + "\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error during login: ").append(e.getMessage()).append("\n");
                } catch (Exception ignore) {}
            }
        });

        // ------------------------------------------------------------
        // COMMUNICATE
        // ------------------------------------------------------------
        communicateButton.setOnAction(event -> {
            if (currentClient == null || currentServer == null) {
                logArea.appendText("Error: Please log in first.\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error: Please log in first.\n");
                } catch (Exception ignore) {}
                return;
            }

            if (currentClient.isTicketExpired() || currentServer.getServerTicket().isExpired()) {
                logArea.appendText("Error: One or both tickets have expired. Please log in again.\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error: One or both tickets have expired. Please log in again.\n");
                } catch (Exception ignore) {}
                return;
            }

            logArea.appendText("Using ticket to communicate with the server...\n");
            try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                logWriter.append("Using ticket to communicate with the server...\n");
            } catch (Exception ignore) {}

            String message = messageField.getText().trim();
            if (message.isEmpty()) {
                message = "[No message typed]";
            }

            try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                SecretKey clientSessionKey = kdc.decryptSessionKey(
                        currentClient.getClientTicket().getEncryptedSessionKey(),
                        kdc.getClientsPrivateKey(currentClient.getId())
                );

                logArea.appendText("Server: Communication established with the client.\n");
                logWriter.append("Server: Communication established with the client.\n");

                String clientKeyBase64 = javax.xml.bind.DatatypeConverter.printBase64Binary(clientSessionKey.getEncoded());
                String encryptedMsg = currentClient.encryptMessage(message, clientSessionKey);

                logArea.appendText(currentServer.getId() + " received: " + message + "\n");
                logWriter.append(currentServer.getId()).append(" received: ").append(message).append("\n");

                String response = currentServer.communicateWithClient(clientKeyBase64, encryptedMsg, kdc);

                logArea.appendText("Message sent and decrypted by the server successfully!\n");
                logWriter.append("Message sent and decrypted by the server successfully!\n");

            } catch (Exception e) {
                logArea.appendText("Error during communication: " + e.getMessage() + "\n");
                try (FileWriter logWriter = new FileWriter("src/Log.txt", true)) {
                    logWriter.append("Error during communication: ").append(e.getMessage()).append("\n");
                } catch (Exception ignore) {}
            }
        });

        VBox root = new VBox(10,
            new HBox(10, new Label("Client ID:"), clientField),
            new HBox(10, new Label("Password:"), passwordField),
            new HBox(10, new Label("Server ID:"), serverField),
            new HBox(10, new Label("Message:"), messageField),
            new HBox(10, registerButton, loginButton, communicateButton),
            new Label("Logs:"),
            logArea
        );
        root.setPadding(new Insets(10));

        Scene scene = new Scene(root, 650, 400);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Kerberos Hybrid System (TicketGrant extends KDC)");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
