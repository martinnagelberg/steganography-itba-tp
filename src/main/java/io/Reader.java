package io;


import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;

public class Reader {

    public static File readCopy(Path in, Path out) throws Exception {

        Path hostFilePath = Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
        return new File(hostFilePath.toString());
    }

    public static void diff(Path in1, Path in2) throws Exception {

        Path hostFilePath = Files.copy(in1, in1, StandardCopyOption.REPLACE_EXISTING);
        Path hostFilePath2 = Files.copy(in2, in2, StandardCopyOption.REPLACE_EXISTING);

        File f1 = new File(hostFilePath.toString());
        File f2 = new File(hostFilePath2.toString());

        try (RandomAccessFile raf = new RandomAccessFile(f1, "r")) {
            try (RandomAccessFile raf2 = new RandomAccessFile(f2, "r")) {

                for (int i = 0; i < 44886; i++) {
                    raf.seek(i);
                    raf2.seek(i);
                    int hostFileByte = raf.read();
                    int hostFileByte2 = raf2.read();

                    if (hostFileByte != hostFileByte2) {
                        System.out.printf("El byte %d difiere => %d vs. %d\n", i, hostFileByte, hostFileByte2);
                    }

                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
