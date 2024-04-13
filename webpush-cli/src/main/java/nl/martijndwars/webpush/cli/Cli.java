package nl.martijndwars.webpush.cli;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import nl.martijndwars.webpush.cli.commands.GenerateKeyCommand;
import nl.martijndwars.webpush.cli.commands.SendNotificationCommand;
import nl.martijndwars.webpush.cli.handlers.GenerateKeyHandler;
import nl.martijndwars.webpush.cli.handlers.SendNotificationHandler;

public final class Cli {

    private static final String GENERATE_KEY = "generate-key";
    private static final String SEND_NOTIFICATION = "send-notification";

    private Cli() {
    }

    public static void main(final String[] args) {
        final var generateKeyCommand = new GenerateKeyCommand();
        final var sendNotificationCommand = new SendNotificationCommand();

        final var jCommander = JCommander.newBuilder()
            .addCommand(GENERATE_KEY, generateKeyCommand)
            .addCommand(SEND_NOTIFICATION, sendNotificationCommand)
            .build();

        try {
            jCommander.parse(args);

            if (jCommander.getParsedCommand() != null) {
                switch (jCommander.getParsedCommand()) {
                    case GENERATE_KEY -> new GenerateKeyHandler(generateKeyCommand).run();
                    case SEND_NOTIFICATION -> new SendNotificationHandler(sendNotificationCommand).run();
                }
            } else {
                jCommander.usage();
            }
        } catch (final ParameterException exception) {
            exception.usage();
        } catch (final Exception exception) {
            exception.printStackTrace();
        }
    }
}
