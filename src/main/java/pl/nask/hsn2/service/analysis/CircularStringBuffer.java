/*
 * Copyright (c) NASK, NCSC
 * 
 * This file is part of HoneySpider Network 2.0.
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

/**
 * Non thread safe.
 */
public class CircularStringBuffer {
	private StringBuilder buffer;

	public CircularStringBuffer(int size) {
		int sizeSafe = size;
		if (size < 1) {
			sizeSafe = 1;
		}
		buffer = new StringBuilder(sizeSafe);
		for (int i = 0; i < sizeSafe; i++) {
			buffer.append(' ');
		}
	}

	public final void add(char ch) {
		buffer.deleteCharAt(0);
		buffer.append(ch);
	}

	public final String getAsString() {
		return buffer.toString();
	}
}
