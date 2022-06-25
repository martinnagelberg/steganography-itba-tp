package io;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Writer {

    public static void write(File out, byte[][] bytes) throws Exception{

        StringBuilder strBuilder = new StringBuilder();

        for (Byte extByte : bytes[1]) {
            char b = (char) (int) extByte;
            if (b != '\0') strBuilder.append((char) (int) extByte);
        }

        Path fileOutPath = Paths.get(out.toString() + strBuilder.toString());
        Files.write(fileOutPath, bytes[0], StandardOpenOption.CREATE);
    }

}
