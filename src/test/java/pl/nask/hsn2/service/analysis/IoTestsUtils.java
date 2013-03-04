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
