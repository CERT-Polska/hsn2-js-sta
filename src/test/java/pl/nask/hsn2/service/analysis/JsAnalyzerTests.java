package pl.nask.hsn2.service.analysis;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
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

	// For malicious/suspicious tests
	private static final String testJsSource = "Shell.Application ADODB.Stream WScript.Shell .exe .bat ms06 ms07 ms08 ms09 "
			+ "shellcode block heap spray exploit overflow savetofile .Exe .eXe .exE .EXe .eXE .ExE .EXE .Bat .bAt .baT .BAt "
			+ ".bAT .BaT top.location document.location window.location document.write document.writeln eval location.replace "
			+ "location.reload location.href document.body.innerhtml myTestMaliciousWordmyTestSuspiciousWord";
	private static final String[] maliciousKeywords = { "Shell.Application", "ADODB.Stream", "WScript.Shell", ".exe", ".bat", "ms06",
			"ms07", "ms08", "ms09", "shellcode", "block", "heap", "spray", "exploit", "overflow", "savetofile", ".Exe", ".eXe", ".exE",
			".EXe", ".eXE", ".ExE", ".EXE", ".Bat", ".bAt", ".baT", ".BAt", ".bAT", ".BaT", "myTestMaliciousWord" };
	private static final String[] suspiciousKeywords = { "top.location", "document.location", "window.location", "document.write",
			"document.writeln", "eval", "location.replace", "location.reload", "location.href", "document.body.innerhtml",
			"myTestSuspiciousWord" };

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
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, whitelist);

		for (int i = 0; i < jsSourcesWhitelistTrue.length; i++) {
			// Prepare temp file.
			File f = new File(prepareTempJsSource(jsSourcesWhitelistTrue[i]));

			JSContextResults result = analyzer.process(i, f);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistTrue[i]);
			Assert.assertTrue(isWhitelisted, "Should be whitelisted");

			// Delete temp file.
			if (!f.delete()) {
				LOGGER.warn("Could not delete temp file: {}", f);
			}
		}
	}

	@Test
	public void whitelistFalseCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, whitelist);

		for (int i = 0; i < jsSourcesWhitelistFalse.length; i++) {
			// Prepare temp file.
			File f = new File(prepareTempJsSource(jsSourcesWhitelistFalse[i]));

			JSContextResults result = analyzer.process(i, f);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistFalse[i]);
			Assert.assertFalse(isWhitelisted, "Should not be whitelisted");

			// Delete temp file.
			if (!f.delete()) {
				LOGGER.warn("Could not delete temp file: {}", f);
			}
		}
	}

	@Test
	public void maliciousSuspiciousCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(maliciousKeywords, suspiciousKeywords, 0, 0, whitelist);

		// Prepare temp file.
		File f = new File(prepareTempJsSource(testJsSource));
		JSContextResults result = analyzer.process(1, f);

		List<String> words = result.getMaliciousKeywordsList();
		for (String word : maliciousKeywords) {
			Assert.assertTrue(words.contains(word), "Malicious word [" + word + "] not found in malicious list.");
			LOGGER.info("Found malicious word: {}", word);
		}
		words = result.getSuspiciousKeywordsList();
		for (String word : suspiciousKeywords) {
			Assert.assertTrue(words.contains(word), "Suspicious word [" + word + "] not found in malicious list.");
			LOGGER.info("Found suspicious word: {}", word);
		}

		// Delete temp file.
		if (!f.delete()) {
			LOGGER.warn("Could not delete temp file: {}", f);
		}
	}

	private String prepareTempJsSource(String source) throws IOException {
		// Create unique path to file.
		File f = new File(System.getProperty("java.io.tmpdir"));
		String tempFileName = f.getAbsolutePath() + File.separator + "hsn2-js-sta_" + counter + System.currentTimeMillis();
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
		LOGGER.info("Temp file created: {}", tempFileName);
		return tempFileName;
	}
}
