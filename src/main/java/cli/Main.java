package cli;

import crypto.CipherWrapper;
import io.Writer;
import io.Reader;
import steganography.*;
import java.io.*;

public class Main {

    public static void main(String... args) throws Exception {

        CipherWrapper.init();

        CMDParser cmdParser = new CMDParser();
        cmdParser.parse(args);

        Stenographer stego = StegoFactory.getStenographer(cmdParser);

        if (cmdParser.isEmbed()) {
            embed(stego, cmdParser);
        } else if (cmdParser.isExtract()){
            extract(stego, cmdParser);
        } else {
            unknownCommand();
        }
    }

    private static void embed(Stenographer stego, CMDParser parser) throws Exception {

        File hostFile = Reader.readCopy(parser.getP().toPath(), parser.getOut().toPath());

        if (hostFile == null) return;
        stego.embed(hostFile, parser.getIn(), 54);
    }

    private static void extract(Stenographer stego, CMDParser parser) throws Exception{

        byte[][] hiddenFileBytes = stego.extract(parser.getP(), 54);
        Writer.write(parser.getOut(), hiddenFileBytes);
    }
    private static void unknownCommand() {
        System.out.println("No method selected");
        System.exit(-1);
    }

}
