import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class icheckerRegistry {

    public static void createRegistry(String registryFilePath, String dirPath, String logFilePath, String hashAlg, String privateKeyPath) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password for decrypting the private key: ");
        String password = scanner.nextLine();

        PrivateKey privateKey = icheckerCert.decryptPrivateKey(privateKeyPath, password);

        try (BufferedWriter regWriter = new BufferedWriter(new FileWriter(registryFilePath));
             BufferedWriter logWriter = new BufferedWriter(new FileWriter(logFilePath, true))) {

            SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String timeStamp = dateFormat.format(new Date());
            logWriter.write(timeStamp + ": Registry file is created at " + registryFilePath + "!\n");

            MessageDigest messageDigest = MessageDigest.getInstance(hashAlg);
            StringBuilder registryContent = new StringBuilder(); // To store all file entries

            AtomicInteger registryCount = new AtomicInteger();
            Files.walk(Paths.get(dirPath))
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            byte[] fileBytes = Files.readAllBytes(path);
                            byte[] fileHash = messageDigest.digest(fileBytes);
                            String fileHashBase64 = Base64.getEncoder().encodeToString(fileHash);

                            regWriter.write(path.toString() + " " + fileHashBase64 + "\n");
                            registryContent.append(path.toString()).append(" ").append(fileHashBase64).append("\n");

                            String logEntryTime = dateFormat.format(new Date());
                            logWriter.write(logEntryTime + ": " + path.toString() + " is added to registry.\n");
                            registryCount.getAndIncrement();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });
            logWriter.write(dateFormat.format(new Date()) + " "+ registryCount + " files are added to the registry and registry creation is finished!\n");

            byte[] regContentHash = messageDigest.digest(registryContent.toString().getBytes());
            byte[] signature = icheckerCert.signData(regContentHash, privateKey);
            String signatureBase64 = Base64.getEncoder().encodeToString(signature);

            regWriter.write("#signature# " + signatureBase64);
            logWriter.write(dateFormat.format(new Date()) + ": Registry creation finished.\n");
        }
    }
}