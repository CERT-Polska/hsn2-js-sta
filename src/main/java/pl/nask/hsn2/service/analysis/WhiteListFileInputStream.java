/*
 * Copyright (c) NASK, NCSC
 * 
 * This file is part of HoneySpider Network 2.1.
 * 
 * This is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
	public final int read() throws IOException {
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
		return isDigit(ch) || isLowerCase(ch) || isUpperCase(ch);
	}

	/**
	 * Checks if given character is digit.
	 * 
	 * @param ch
	 *            Character to check.
	 * @return True if it's digit. False otherwise.
	 */
	private boolean isDigit(char ch) {
		return ch >= '0' && ch <= '9';
	}

	/**
	 * Checks if given character is upper case letter [A-Z].
	 * 
	 * @param ch
	 *            Character to check.
	 * @return True if it's upper case letter. False otherwise.
	 */
	private boolean isUpperCase(char ch) {
		return ch >= 'A' && ch <= 'Z';
	}

	/**
	 * Checks if given character is lower case letter [a-z].
	 * 
	 * @param ch
	 *            Character to check.
	 * @return True if it's lower case letter. False otherwise.
	 */
	private boolean isLowerCase(char ch) {
		return ch >= 'a' && ch <= 'z';
	}
	
	@Override
	public final void close() throws IOException {
		is.close();
	}
}
