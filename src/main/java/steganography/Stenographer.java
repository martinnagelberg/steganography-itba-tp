package steganography;

import java.io.File;

public interface Stenographer {
    void embed(File hostFile, File fileToHide, long bytesToSkip);
    byte[][] extract(File hostFile, long bytesToSkip);
}
