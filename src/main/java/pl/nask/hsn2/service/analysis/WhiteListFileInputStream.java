package pl.nask.hsn2.service.analysis;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * File input stream with changed 'read()' implementation to filter read characters and return only [a-zA-Z0-9]. This
 * implementation is used to create MD5 hash for white listing check by HSN2 JS-STA service.
 */
public class WhiteListFileInputStream extends InputStream {
	private final InputStream is;

	public WhiteListFileInputStream(InputStream is) throws FileNotFoundException {
		this.is = is;
	}

	/**
	 * Returns only [a-zA-Z0-9] characters. All other characters are ignored. Returns -1 for EOF.
	 */
	@Override
	public int read() throws IOException {
		int result;
		do {
			result = is.read();
		} while (result != -1 && !isCharAccepted((char) result));
		return result;
	}

	/**
	 * Checks if character is accepted for white listing.
	 * 
	 * @param ch
	 * @return True if character has been accepted and should be present in trimmed string, otherwise false.
	 */
	private boolean isCharAccepted(char ch) {
		if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')) {
			return true;
		} else {
			return false;
		}
	}
}
