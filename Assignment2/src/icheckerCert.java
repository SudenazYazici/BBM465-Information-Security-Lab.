import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;

public class icheckerCert {
    
    private static final String PRIVATE_KEY_TEXT = "This is the private key file";

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static PrivateKey decryptPrivateKey(String privateKeyPath, String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] passwordHash = md.digest(password.getBytes());
        SecretKey aesKey = new SecretKeySpec(passwordHash, "AES");

        try (FileInputStream fis = new FileInputStream(privateKeyPath);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            byte[] encryptedPrivateKey = (byte[]) ois.readObject();
            String additionalText = (String) ois.readObject();

            if (!PRIVATE_KEY_TEXT.equals(additionalText)) {
                throw new SecurityException("Incorrect password or private key file is corrupted.");
            }

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedPrivateKey = cipher.doFinal(encryptedPrivateKey);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decryptedPrivateKey));
        }
    }

    public static void createSelfSignedCertificate(String privateKeyPath, String certificatePath) throws Exception {

        File certFile = new File(certificatePath);
        if (certFile.exists() && certFile.length() == 0) {
            certFile.delete();
        }
    
        String keystorePath = "tempKeystore.jks";
        String keystorePassword = "keystorepassword";
        String alias = "selfsign";
    
        // 1. Creating keystore and adding certificate
        String keytoolCommand = String.format(
        "keytool -genkeypair -alias %s -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -keystore %s -storepass %s -dname \"CN=default\" -validity 365 -keypass %s",
        alias, keystorePath, keystorePassword, keystorePassword);
        
        Process process = Runtime.getRuntime().exec(keytoolCommand);
        
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        String line;
        while ((line = errorReader.readLine()) != null) {
            System.err.println(line);
        }
    
        process.waitFor();
    
        if (process.exitValue() == 0) {
            System.out.println("Keystore (.jks) created successfully.");
        } else {
            System.err.println("Error in creating keystore.");
            return;
        }
        // Extracting the private key from keystore and then encrypting with AES to save to key file
        try (FileInputStream keystoreInputStream = new FileInputStream(keystorePath)) {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(keystoreInputStream, keystorePassword.toCharArray());

            Key key = keystore.getKey(alias, keystorePassword.toCharArray());
            if (key instanceof PrivateKey) {
                // Taking password from user
                Scanner scanner = new Scanner(System.in);
                System.out.print("Enter password for encrypting the private key: ");
                String password = scanner.nextLine();

                // Hashing the key with MD5 to convert it to AES key
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] passwordHash = md.digest(password.getBytes());
                SecretKey aesKey = new SecretKeySpec(passwordHash, "AES");

                // Encrypting the private key with AES
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] encryptedPrivateKey = cipher.doFinal(key.getEncoded());

                // Saving the encrypted key to a file
                try (FileOutputStream fos = new FileOutputStream(privateKeyPath);
                    ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                    oos.writeObject(encryptedPrivateKey);
                    oos.writeObject(PRIVATE_KEY_TEXT);
                }
            }
        }
        // 2. Exporting the certificate
        String exportCommand = String.format(
                "keytool -exportcert -alias %s -keystore %s -storepass %s -file %s",
                alias, keystorePath, keystorePassword, certificatePath);
        
        Process exportProcess = Runtime.getRuntime().exec(exportCommand);
    
        BufferedReader exportErrorReader = new BufferedReader(new InputStreamReader(exportProcess.getErrorStream()));
        while ((line = exportErrorReader.readLine()) != null) {
            System.err.println(line);
        }
    
        exportProcess.waitFor();
    
        if (exportProcess.exitValue() == 0) {
            System.out.println("Certificate exported to .cer file successfully.");
        } else {
            System.err.println("Error in exporting certificate.");
            return;
        }
    

    }
    
    public static PublicKey loadCertificatePublicKey(String certPath) throws Exception {
        try (FileInputStream fis = new FileInputStream(certPath)) {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate cert = certFactory.generateCertificate(fis); // using java.security.cert.Certificate
            return cert.getPublicKey();
        }
    }
    
}
