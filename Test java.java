import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.sftp.client.SftpClient;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class MINAKeyConnect {

    public static void main(String[] args) throws Exception {

        String sftpHost = "your_sftp_host";
        String sftpPort = "your_sftp_port";
        String sftpUser = "your_sftp_username";
        String privateKeyFilePath = "path_to_your_encrypted_private_key_file";
        String decryptionPassword = "your_decryption_password";
        String sftpPath = "your_sftp_path";

        // Initialize Bouncy Castle as a security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Read and decrypt the private key file
        PrivateKey privateKey = decryptPrivateKey(privateKeyFilePath, decryptionPassword);

        // Initialize SSH client
        SshClient client = SshClient.setUpDefaultClient();
        client.setServerKeyVerifier(AcceptAllServerKeyVerifier.INSTANCE);
        client.start();

        // Set up key identity provider with the decrypted private key
        KeyIdentityProvider keyIdentityProvider = KeyIdentityProvider.wrap(Collections.singletonList(privateKey));

        // Connect to the SFTP server
        ClientSession session = client.connect(sftpUser, sftpHost, Integer.parseInt(sftpPort)).verify().getSession();
        session.addPublicKeyIdentity(privateKey);
        session.auth().verify();

        // Create an SFTP client session
        SftpClient sftpClient = SftpClientFactory.instance().createSftpClient(session);
        SftpClient.CloseableHandle dirHandle = sftpClient.openDir(sftpPath);
        List<SftpClient.DirEntry> files = StreamSupport.stream(sftpClient.listDir(dirHandle).spliterator(), false)
                .collect(Collectors.toList());

        // Perform all your SFTP operations like reading all files and copying to destination path

        // Close the SFTP client
        sftpClient.close();

        // Close the SSH session
        session.close();
    }

    private static PrivateKey decryptPrivateKey(String privateKeyFilePath, String password) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyFilePath))) {
            Object object = pemParser.readObject();

            if (object instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair encryptedKeyPair = (PEMEncryptedKeyPair) object;
                JcePEMDecryptorProviderBuilder decryptorProviderBuilder = new JcePEMDecryptorProviderBuilder();
                PEMKeyPair keyPair = encryptedKeyPair.decryptKeyPair(decryptorProviderBuilder.build(password.toCharArray()));
                return new JcaPEMKeyConverter().getPrivateKey(keyPair.getPrivateKeyInfo());
            } else if (object instanceof PEMKeyPair) {
                PEMKeyPair keyPair = (PEMKeyPair) object;
                return new JcaPEMKeyConverter().getPrivateKey(keyPair.getPrivateKeyInfo());
            } else {
                throw new IllegalArgumentException("Unsupported key format");
            }
        }
    }
}
