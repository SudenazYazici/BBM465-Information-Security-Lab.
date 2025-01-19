public class ichecker {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: ichecker <command> [options]");
            return;
        }

        try {
            switch (args[0]) {
                case "createCert":
                    if (args.length != 5 || !args[1].equals("-k") || !args[3].equals("-c")) {
                        System.out.println("Usage: ichecker createCert -k <PrivateKeyFilePath> -c <CertificateFilePath>");
                        return;
                    }
                    String privateKeyPath = args[2];
                    String certificatePath = args[4];
                    icheckerCert.createSelfSignedCertificate(privateKeyPath, certificatePath);
                    break;

                case "createReg":
                    if (args.length != 11 || !args[1].equals("-r") || !args[3].equals("-p") || !args[5].equals("-l") || !args[7].equals("-h") || !args[9].equals("-k")) {
                        System.out.println("Usage: ichecker createReg -r <RegistryFilePath> -p <DirectoryPath> -l <LogFilePath> -h <HashAlgorithm> -k <PrivateKeyFilePath>");
                        return;
                    }
                    String registryFilePath = args[2];
                    String dirPath = args[4];
                    String logFilePath = args[6];
                    String hashAlg = args[8];
                    String privKeyPath = args[10];
                    icheckerRegistry.createRegistry(registryFilePath, dirPath, logFilePath, hashAlg, privKeyPath);
                    break;

                case "check":
                    if (args.length != 11 || !args[1].equals("-r") || !args[3].equals("-p") || !args[5].equals("-l") || !args[7].equals("-h") || !args[9].equals("-c")) {
                        System.out.println("Usage: ichecker check -r <RegistryFilePath> -p <DirectoryPath> -l <LogFilePath> -h <HashAlgorithm> -c <CertificateFilePath>");
                        return;
                    }
                    String registryFilePathcheck = args[2];
                    String dirPathcheck = args[4];
                    String logFilePathcheck = args[6];
                    String hashAlgcheck = args[8];
                    String certPathcheck = args[10];
                    icheckerIntegrity.checkIntegrity(registryFilePathcheck, dirPathcheck, logFilePathcheck, hashAlgcheck, certPathcheck);
                    break;

                default:
                    System.out.println("Invalid command.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
