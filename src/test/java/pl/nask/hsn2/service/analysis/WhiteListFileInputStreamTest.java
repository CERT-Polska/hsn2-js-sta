package pl.nask.hsn2.service.analysis;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

import junit.framework.Assert;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

public class WhiteListFileInputStreamTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(WhiteListFileInputStreamTest.class);
	private static final String EXPECTED_RESULT = "abcABC";
	private static final String INPUT_STRING = "-{!a $}b^c&()A*B[_]C/\\";

	@Test
	public void whiteListFileInputStreamTest() throws Exception {
		File f = IoTestsUtils.prepareTempFile(INPUT_STRING, WhiteListFileInputStreamTest.class.getSimpleName());
		StringBuilder sb = new StringBuilder();
		try (InputStream is = new WhiteListFileInputStream(new FileInputStream(f))) {
			while (readOneChar(is, sb)) {
			}
		}
		Assert.assertEquals(EXPECTED_RESULT, sb.toString());

		// Delete temp file.
		try {
			Files.delete(f.toPath());
		} catch (IOException e) {
			LOGGER.warn("Could not delete temp file. (file={}, reason={})", f.getAbsolutePath(), e.getMessage());
		}
	}

	/**
	 * Read one char from input stream to string builder.
	 * 
	 * @param is
	 *            Input stream to read from.
	 * @param sb
	 *            String builder to append to.
	 * @return True if successful char read. False if EOF.
	 * @throws IOException
	 */
	private boolean readOneChar(InputStream is, StringBuilder sb) throws IOException {
		int chInt = is.read();
		if (chInt == -1) {
			return false;
		} else {
			sb.append((char) chInt);
			return true;
		}
	}
}
