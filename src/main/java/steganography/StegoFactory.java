package steganography;

import cli.CMDParser;

public class StegoFactory {

    public static Stenographer getStenographer(CMDParser parser){

        String stegoStrategy = parser.getSteg();

        if(stegoStrategy == null){
            return null;
        }

        switch (stegoStrategy.toUpperCase()){
            case "LSB1": return new LSB1(parser);
            case "LSB4": return new LSB4(parser);
            case "LSBI": return new LSBI(parser);
        }

        return null;
    }

}
