package cli;

import crypto.CipherAlgorithm;
import crypto.CipherOperationMode;
import org.apache.commons.cli.*;

import java.io.File;

public class CMDParser {

    private static Options options;
    private static CommandLineParser parser;
    private static HelpFormatter formatter;
    private static CommandLine cmd;

    public CMDParser(){}

    public void parse(String... args) {

        options = new Options();

        org.apache.commons.cli.Option embed = new org.apache.commons.cli.Option("embed", false, "Hide data in host");
        embed.setRequired(false);
        options.addOption(embed);

        org.apache.commons.cli.Option extract = new org.apache.commons.cli.Option("extract", false, "Extract data from host");
        extract.setRequired(false);
        options.addOption(extract);

        org.apache.commons.cli.Option in = new org.apache.commons.cli.Option("in", true, "Hiding file");
        in.setRequired(false);
        options.addOption(in);

        org.apache.commons.cli.Option p = new org.apache.commons.cli.Option("p", true, "Host file name");
        p.setRequired(false);
        options.addOption(p);

        org.apache.commons.cli.Option out = new org.apache.commons.cli.Option("out", true, "Out file name");
        out.setRequired(false);
        options.addOption(out);

        org.apache.commons.cli.Option steg = new org.apache.commons.cli.Option("steg", true, "Stego strategy");
        steg.setRequired(false);
        options.addOption(steg);

        org.apache.commons.cli.Option a = new org.apache.commons.cli.Option("a", true, "Encryption algorithm");
        a.setRequired(false);
        options.addOption(a);

        org.apache.commons.cli.Option m = new org.apache.commons.cli.Option("m", true, "Encryption mode");
        m.setRequired(false);
        options.addOption(m);

        org.apache.commons.cli.Option pass = new Option("pass", true, "Encryption password");
        pass.setRequired(false);
        options.addOption(pass);

        parser = new DefaultParser();
        formatter = new HelpFormatter();

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println("Couldn't parse the cli: " + e);
            formatter.printHelp("stegobmp", options);
            System.exit(1);
        }
    }

    public boolean isEmbed() {
        return cmd.hasOption("embed");
    }

    public boolean isExtract() {
        return cmd.hasOption("extract");
    }

    public String getSteg() {

        if (cmd.hasOption("steg")){
            return cmd.getOptionValue("steg");
        }

        return null;
    }

    public CipherAlgorithm getA() {

        if (cmd.hasOption("a")) {

            switch (cmd.getOptionValue("a").toLowerCase()) {
                case "aes128":
                    return CipherAlgorithm.AES128;
                case "aes192":
                    return CipherAlgorithm.AES192;
                case "aes256":
                    return CipherAlgorithm.AES256;
                case "des":
                    return CipherAlgorithm.DES;
                default:
                    return CipherAlgorithm.AES128;
            }
        }

        return CipherAlgorithm.AES128;
    }

    public CipherOperationMode getM() {

        if (cmd.hasOption("m")){
            switch (cmd.getOptionValue("m").toLowerCase()) {
                case "ecb":
                    return CipherOperationMode.ECB;
                case "cbc":
                    return CipherOperationMode.CBC;
                case "cfb":
                    return CipherOperationMode.CFB;
                case "ofb":
                    return CipherOperationMode.OFB;
                default:
                    return CipherOperationMode.CBC;
            }
        }

        return CipherOperationMode.CBC;
    }

    public String getPass() {
        if (cmd.hasOption("pass")){
            return cmd.getOptionValue("pass");
        }

        return null;
    }

    public File getOut() {

        if (cmd.hasOption("out")){
            return new File(cmd.getOptionValue("out"));
        }

        return null;
    }

    public File getIn() {
        if (cmd.hasOption("in")){
            return new File(cmd.getOptionValue("in"));
        }

        return null;
    }

    public File getP() {
        if (cmd.hasOption("p")){
            return new File(cmd.getOptionValue("p"));
        }

        return null;
    }

}