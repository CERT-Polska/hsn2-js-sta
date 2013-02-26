package pl.nask.hsn2.service.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import mockit.Mocked;
import mockit.NonStrictExpectations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;

public class JsAnalyzerTests {
	private static final Logger LOGGER = LoggerFactory.getLogger(JsAnalyzerTests.class);
	private Set<String> whitelist;
	private String[] jsSourcesWhitelistTrue = { "alert(1+'-');", " alert ( \"1\" ) ; ", " alert \n\t\n\t  ('1');", "\nalert(1)\t;\n" };
	private String[] jsSourcesWhitelistFalse = { "alert(2);", "alertThis(\"1\");", "alert\n\t\n\t(1+2);", "\nalert('a');alert(1)\t;\n" };
	private int counter = 0;

	@BeforeClass
	private void testInit() {
		whitelist = new HashSet<String>();
		whitelist.add("f3312b1a03e36409470c404bd2f81e6f");
	}

	private void mockObjects() {
		new NonStrictExpectations() {
			@Mocked({ "classifyString" })
			JSWekaAnalyzer analyzer;
			{
				analyzer.classifyString(withInstanceOf(File.class));
				result = JSClass.UNCLASSIFIED;
			}
		};
	}

	@Test
	public void whitelistTrueCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, "", whitelist);

		for (int i = 0; i < jsSourcesWhitelistTrue.length; i++) {
			String filename = prepareTempJsSource(jsSourcesWhitelistTrue[i]);

			// test
			JSContextResults result = analyzer.process(i, new File(filename));
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistTrue[i]);
			Assert.assertTrue(isWhitelisted, "Should be whitelisted");
		}
	}

	@Test
	public void whitelistFalseCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, "", whitelist);

		for (int i = 0; i < jsSourcesWhitelistFalse.length; i++) {
			String filename = prepareTempJsSource(jsSourcesWhitelistFalse[i]);

			// test
			JSContextResults result = analyzer.process(i, new File(filename));
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistFalse[i]);
			Assert.assertFalse(isWhitelisted, "Should not be whitelisted");
		}
	}

	private String prepareTempJsSource(String source) {
		// Create unique path to file.
		String fileName = System.getProperty("java.io.tmpdir") + counter + "hsn2-js-sta_" + System.currentTimeMillis();
		counter++;
		File f;
		do {
			fileName += "-";
			f = new File(fileName);
		} while (f.exists());

		// Write source to file.
		BufferedWriter bw = null;
		try {
			bw = new BufferedWriter(new FileWriter(f));
			bw.write(source);
		} catch (IOException e) {
			// WST fix exception
			e.printStackTrace();
		} finally {
			if (bw != null) {
				try {
					bw.close();
				} catch (IOException e) {
					// WST fix exception
					e.printStackTrace();
				}
			}
		}

		// Return path file.
		LOGGER.info("Temp file created: {}", fileName);
		return fileName;
	}
}
