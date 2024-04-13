package nl.martijndwars.webpush.cli.handlers;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

import nl.martijndwars.webpush.util.ECKeys;
import nl.martijndwars.webpush.cli.commands.GenerateKeyCommand;

public class GenerateKeyHandler implements Handler {

    private final GenerateKeyCommand generateKeyCommand;

    public GenerateKeyHandler(GenerateKeyCommand generateKeyCommand) {
        this.generateKeyCommand = generateKeyCommand;
    }

    @Override
    public void run() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, InvalidParameterSpecException {
        KeyPair keyPair = ECKeys.generateKeyPair();

        ECPublicKey publicKey   = (ECPublicKey) keyPair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        byte[] encodedPublicKey  = ECKeys.encode(publicKey);
        byte[] encodedPrivateKey = ECKeys.encode(privateKey);

        System.out.println("PublicKey:");
        System.out.println(Base64.getUrlEncoder().encodeToString(encodedPublicKey));

        System.out.println("PrivateKey:");
        System.out.println(Base64.getUrlEncoder().encodeToString(encodedPrivateKey));

        if (generateKeyCommand.hasPublicKeyFile())
            writePem(keyPair.getPublic(), Paths.get(generateKeyCommand.getPublicKeyFile()));
    }

    private void writePem(final Key key, final Path path) throws IOException {
        // Done similar to sun.security.tools.KeyTool.
        try (var writer =
                 Files.newBufferedWriter(path, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            writer.write("-----BEGIN Key-----\n");
            // Use line wrapping at 64 characters similar to how Bouncy Castle's PemWriter used to.
            writeWrapped(writer, Base64.getEncoder().encodeToString(key.getEncoded()), 64);
            writer.write("-----END Key-----\n");
        }
    }

    @SuppressWarnings("SameParameterValue")
    private static void writeWrapped(final Writer writer, final String text, final int maxLineLength)
            throws IOException {
        for (int beginIndex = 0; beginIndex < text.length(); beginIndex += maxLineLength) {
            final int endIndex = Math.min(text.length(), beginIndex + maxLineLength);
            writer.write(text.substring(beginIndex, endIndex));
            writer.write('\n');
        }
    }
}
