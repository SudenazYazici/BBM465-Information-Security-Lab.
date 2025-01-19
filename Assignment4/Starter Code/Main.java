import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.Stage;

public class Main extends Application {
    
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
        
        VBox root = new VBox(10,
            new HBox(10, clientLabel, clientField),
            new HBox(10, passwordLabel, passwordField),
            new HBox(10, serverLabel, serverField),
			new HBox(10, messageLabel, messageField),
            new HBox(10, registerButton, loginButton, communicateButton),
            new Label("Logs:"),
            logArea
        );
        root.setPadding(new Insets(10));

        Scene scene = new Scene(root, 600, 400);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Kerberos Hybrid System");
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
