package steganography;

import cli.CMDParser;
import crypto.CipherWrapper;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class LSB1 implements Stenographer {

    private CMDParser parser;

    public LSB1(CMDParser parser) { this.parser = parser; }

    @Override
    public void embed(File hostFile, File fileToHide, long bytesToSkip) {

        try (RandomAccessFile raf = new RandomAccessFile(hostFile, "rw")){

            long pos = bytesToSkip;
            raf.seek(pos);
            String name = fileToHide.getName();
            String spl[] = name.split("\\.");
            String ext = spl.length > 0 ? "." + spl[spl.length - 1] + "\0" : "\0";
            byte fileBytes[] = Files.readAllBytes(fileToHide.toPath());
            int size = fileBytes.length;
            long hostSize = hostFile.length();

            byte sizeBytes[] = ByteBuffer.allocate(4).putInt(size).array();
            byte extBytes[] = ext.getBytes();
            byte bytes[] = new byte[fileBytes.length + sizeBytes.length + extBytes.length];
            System.arraycopy(sizeBytes, 0, bytes, 0, sizeBytes.length);
            System.arraycopy(fileBytes, 0, bytes, sizeBytes.length, fileBytes.length);
            System.arraycopy(extBytes, 0, bytes, sizeBytes.length + fileBytes.length, extBytes.length);

            if(!(this.parser.getPass() == null)) {
                CipherWrapper c = new CipherWrapper(this.parser.getA(), this.parser.getM());
                byte[] bytesEnc = c.encrypt(bytes, this.parser.getPass());

                size = bytesEnc.length;
                bytes = new byte[bytesEnc.length + 4];
                sizeBytes = ByteBuffer.allocate(4).putInt(size).array();

                System.arraycopy(sizeBytes, 0, bytes, 0, sizeBytes.length);
                System.arraycopy(bytesEnc, 0, bytes, sizeBytes.length, bytesEnc.length);
            }

            if(hostSize - 54 < size * 8) {
                System.out.println("Error: Not enough space to hide file. (Max space: " + (int)((hostSize - 54) / 8) + ")");
                return;
            }

            for (Byte b: bytes) {
                int newByte;
                int byteToChange;

                for (int i = 7; i >=0; i--) {
                    byteToChange = raf.read();
                    newByte = (byteToChange & 0b11111110) | ((b>>i) & 1);
                    raf.seek(pos);
                    raf.write(newByte);
                    pos++;
                }
            }
        } catch (IOException e) {
            System.out.println("Error");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public byte[][] extract(File hostFile, long bytesToSkip) {

        try (RandomAccessFile raf = new RandomAccessFile(hostFile, "r")){

            //Skip header and get first 4 bytes which contain stego size
            long pos = bytesToSkip;
            byte[] sizeBytes = new byte[4];
            for (int j = 0; j < 4; j++) {
                int hiddenFileByte = 0;
                int hostFileByte;
                for (int k = 7; k >= 0; pos++, k--) {
                    raf.seek(pos);
                    hostFileByte = raf.read();
                    hiddenFileByte = (hiddenFileByte | ((hostFileByte & 1) << k));
                }
                sizeBytes[j] = (byte) hiddenFileByte;
            }

            //Read stego content
            int hiddenFileSize = ByteBuffer.wrap(sizeBytes).getInt();
            //System.out.printf("Tamaño: %d\n", hiddenFileSize);
            byte bytes[] = new byte[hiddenFileSize];
            for (int i = 0; i < hiddenFileSize; i++) {
                int hiddenFileByte = 0;
                int hostFileByte;

                //Get LSB
                for (int j = 7; j >= 0; pos++, j--) {
                    raf.seek(pos);
                    hostFileByte = raf.read();
                    hiddenFileByte = (byte)(hiddenFileByte | ((hostFileByte & 1) << j));
                }
                bytes[i] = (byte) hiddenFileByte;
            }

            byte hData[][] = new byte[2][];

            //If data seems to be encrypted, we handle decryption
            if(!(this.parser.getPass() == null)) {
                CipherWrapper c = new CipherWrapper(this.parser.getA(), this.parser.getM());
                byte[] decBytes = c.decrypt(bytes, this.parser.getPass());
                byte[] origSize = Arrays.copyOfRange(decBytes, 0, 4);
                int origSizeInt = ByteBuffer.wrap(origSize).getInt();
                hData[0] = Arrays.copyOfRange(decBytes, 4, 4 + origSizeInt);
                hData[1] = Arrays.copyOfRange(decBytes, 4 + origSizeInt, decBytes.length);
                return hData;
            }

            byte hiddenFileByte = -1;
            List<Byte> extBytes = new LinkedList<>();
            for (int j = 0; hiddenFileByte != 0; j++) {
                hiddenFileByte = 0;
                for (int k = 7; k >= 0; pos++) {
                    raf.seek(pos);
                    int hostFileByte = raf.read();
                    hiddenFileByte = (byte) (hiddenFileByte | ((hostFileByte & 1) << k));
                    k--;
                }
                extBytes.add(hiddenFileByte);
            }
            byte extbytes[] = new byte[extBytes.size()];
            for (int i = 0; i < extbytes.length; i++) {
                extbytes[i] = extBytes.get(i);
            }

            hData[0] = bytes;
            hData[1] = extbytes;

            return hData;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

}
