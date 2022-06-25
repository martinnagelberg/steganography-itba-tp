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

public class LSBI implements Stenographer {

    private CMDParser parser;
    public LSBI(CMDParser parser) {this.parser = parser;}

    @Override
    public void embed(File hostFile, File fileToHide, long bytesToSkip) {

        try (RandomAccessFile raf = new RandomAccessFile(hostFile, "rw")){

            long pos = bytesToSkip + 4; //Add 4 bytes to save bit inversion pattern
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

            if(hostSize - 58 < size * 8) {
                System.out.println("Error: Not enough space to hide file. (Max space: " + (int)((hostSize - 58) / 8) + ")");
                return;
            }

            int[] invMatrix = new int[4];
            for (int bitPat = 0; bitPat < 4; bitPat++) {
                int mod = 0;
                int unmod = 0;

                for (Byte b : bytes) {
                    for (int i = 0; i < 8; i++) {

                        int newB = ((b >> (7-i)) & 1);
                        raf.seek(pos);
                        int byteToChange = raf.read();

                        int check = (byteToChange & 0b00000110) >> 1;

                        if (bitPat == check) {
                            if ((byteToChange & 1) != newB) {
                                mod += 1;
                            } else {
                                unmod +=1;
                            }
                        }

                        pos++;
                    }
                }

                invMatrix[bitPat] =  (mod > unmod) ? 1 : 0;
            }

            pos = bytesToSkip;
            for (int bitPat = 0; bitPat < 4; bitPat++) {
                int byteToChange = raf.read();
                int newByte = ((byteToChange & 0b11111110) | invMatrix[bitPat]);
                raf.seek(pos);
                raf.write(newByte);
                pos++;
            }

            for (Byte b: bytes) {
                for (int i = 7; i >=0; i--) {

                    int byteToChange = raf.read();
                    int check = (byteToChange & 0b00000110) >> 1;
                    int lastBit = (((b>>i) & 1));
                    int newByte = ((byteToChange & 0b11111110) | lastBit ^ invMatrix[check]);
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

            //Skip header and get first 4 bytes which contain pattern data
            long pos = bytesToSkip;
            int[] invMatrix = new int[4];
            for (int j = 0; j < 4; j++) {
                int hiddenFileByte = 0;
                int hostFileByte;
                raf.seek(pos);
                hostFileByte = raf.read();
                hiddenFileByte = ((hostFileByte & 1));
                //System.out.printf("Byte pattern: %s - %d -> %d\n",  Integer.toBinaryString(hostFileByte), hostFileByte, hiddenFileByte);
                invMatrix[j] = hiddenFileByte;
                pos++;
            }

            //Get second 4 bytes which contain stego size
            byte[] sizeBytes = new byte[4];
            for (int j = 0; j < 4; j++) {
                int hiddenFileByte = 0;
                int hostFileByte;
                for (int k = 7; k >= 0; pos++, k--) {
                    raf.seek(pos);
                    hostFileByte = raf.read();

                    int check = (hostFileByte & 0b00000110) >> 1;
                    int lastBit = ((hostFileByte & 1) ^ invMatrix[check]);

                    hiddenFileByte = (hiddenFileByte | ((lastBit) << k));
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
                    int check = (hostFileByte & 0b00000110) >> 1;
                    int lastBit = ((hostFileByte & 1) ^ invMatrix[check]);

                    hiddenFileByte = (byte) (hiddenFileByte | ((lastBit) << j));
                }
                bytes[i] = (byte) hiddenFileByte;
            }

            byte hData[][] = new byte[2][];

            //If data seems to be encrypted, we handle decryption
            if(!(this.parser.getPass() == null)) {
                CipherWrapper c = new CipherWrapper(this.parser.getA(), this.parser.getM());
                bytes = c.decrypt(bytes, this.parser.getPass());
                byte[] origSize = Arrays.copyOfRange(bytes, 0, 4);
                int origSizeInt = ByteBuffer.wrap(origSize).getInt();
                hData[0] = Arrays.copyOfRange(bytes, 4, 4 + origSizeInt);
                hData[1] = Arrays.copyOfRange(bytes, 4 + origSizeInt, bytes.length);
                return hData;
            }

            byte hiddenFileByte = -1;
            List<Byte> extBytes = new LinkedList<>();
            for (int j = 0; hiddenFileByte != 0; j++) {
                hiddenFileByte = 0;
                for (int k = 7; k >= 0; pos++) {
                    raf.seek(pos);
                    int hostFileByte = raf.read();
                    int check = (hostFileByte & 0b00000110) >> 1;
                    int lastBit = ((hostFileByte & 1) ^ invMatrix[check]);

                    hiddenFileByte = (byte) (hiddenFileByte | ((lastBit) << k));
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