package nl.martijndwars.webpush.cli.handlers;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.*;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import nl.martijndwars.webpush.Utils;
import nl.martijndwars.webpush.cli.commands.GenerateKeyCommand;

public class GenerateKeyHandler implements Handler {

    private final GenerateKeyCommand generateKeyCommand;

    public GenerateKeyHandler(GenerateKeyCommand generateKeyCommand) {
        this.generateKeyCommand = generateKeyCommand;
    }

    @Override
    public void run() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
        KeyPair keyPair = generateKeyPair();

        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        byte[] encodedPublicKey = Utils.encode(publicKey);
        byte[] encodedPrivateKey = Utils.encode(privateKey);

        if (generateKeyCommand.hasPublicKeyFile()) {
            writeKey(keyPair.getPublic(), new File(generateKeyCommand.getPublicKeyFile()));
        }

        System.out.println("PublicKey:");
        System.out.println(Base64.getUrlEncoder().encodeToString(encodedPublicKey));

        System.out.println("PrivateKey:");
        System.out.println(Base64.getUrlEncoder().encodeToString(encodedPrivateKey));
    }

    /**
     * Generate an EC keypair on the prime256v1 curve.
     */
    public KeyPair generateKeyPair() throws InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchAlgorithmException {
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(Utils.CURVE);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Utils.ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(parameterSpec);

        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Write the given key to the given file.
     */
    private void writeKey(Key key, File file) throws IOException {
        file.createNewFile();

        try (PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(file)))) {
            PemObject pemObject = new PemObject("Key", key.getEncoded());

            pemWriter.writeObject(pemObject);
        }
    }
}
