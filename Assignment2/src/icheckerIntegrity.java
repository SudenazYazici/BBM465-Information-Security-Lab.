import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.*;

public class icheckerIntegrity {

    public static void checkIntegrity(String registryFilePath, String dirPath, String logFilePath, String hashAlg, String certPath) throws Exception {
        try (BufferedWriter logWriter = new BufferedWriter(new FileWriter(logFilePath, true))) {
            SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
            String timeStamp = dateFormat.format(new Date());

            PublicKey publicKey = icheckerCert.loadCertificatePublicKey(certPath);
            List<String> registryLines = Files.readAllLines(Paths.get(registryFilePath));
            String signatureLine = registryLines.get(registryLines.size() - 1).trim();

            if (!signatureLine.startsWith("#signature#")) {
                throw new IllegalArgumentException("Signature line format is incorrect");
            }

            byte[] signature = Base64.getDecoder().decode(signatureLine.replace("#signature# ", ""));
            MessageDigest messageDigest = MessageDigest.getInstance(hashAlg);

            StringBuilder registryContent = new StringBuilder();
            for (String line : registryLines.subList(0, registryLines.size() - 1)) {
                registryContent.append(line).append("\n");
            }

            byte[] contentHash = messageDigest.digest(registryContent.toString().getBytes());
            if (!verifySignature(contentHash, signature, publicKey)) {
                logWriter.write(timeStamp + ": Registry file verification failed! Signature does not match.\n");
                System.out.println("Registry file verification failed.");
                return;
            }

            logWriter.write(timeStamp + ": Registry file verification successful!\n");

            Map<String, String> registryMap = new HashMap<>();
            for (String line : registryLines.subList(0, registryLines.size() - 1)) {
                String[] parts = line.split(" ");
                registryMap.put(parts[0], parts[1]);
            }

            Set<String> currentFiles = new HashSet<>();
            Files.walk(Paths.get(dirPath))
                    .filter(Files::isRegularFile)
                    .forEach(path -> {
                        try {
                            byte[] fileBytes = Files.readAllBytes(path);
                            byte[] fileHash = messageDigest.digest(fileBytes);
                            String fileHashBase64 = Base64.getEncoder().encodeToString(fileHash);
                            currentFiles.add(path.toString());

                            if (!registryMap.containsKey(path.toString())) {
                                logWriter.write(timeStamp + ": " + path + " is created\n");
                            } else if (!registryMap.get(path.toString()).equals(fileHashBase64)) {
                                logWriter.write(timeStamp + ": " + path + " is altered\n");
                            }
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    });

            for (String filePath : registryMap.keySet()) {
                if (!currentFiles.contains(filePath)) {
                    logWriter.write(timeStamp + ": " + filePath + " is deleted\n");
                }
            }

            logWriter.flush();
            System.out.println("Directory integrity check completed.");
        }
    }

    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }
}