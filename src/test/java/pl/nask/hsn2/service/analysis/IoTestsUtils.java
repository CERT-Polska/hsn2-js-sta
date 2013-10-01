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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public final class IoTestsUtils {
	/**
	 * Utility class. Can't instantiate.
	 */
	private IoTestsUtils() {
	}

	public static File prepareTempFile(String source, String additionalNameAttr) throws IOException {
		// Create unique path to file.
		File f = new File(System.getProperty("java.io.tmpdir"));
		String tempFileName = f.getAbsolutePath() + File.separator + "hsn2-js-sta_" + additionalNameAttr + System.currentTimeMillis();
		while (true) {
			f = new File(tempFileName);
			if (!f.exists()) {
				break;
			}
			tempFileName += "-";
		}

		// Write source to file.
		BufferedWriter bw = new BufferedWriter(new FileWriter(f));
		bw.write(source);
		bw.close();

		// Return path file.
		return f;
	}
}
