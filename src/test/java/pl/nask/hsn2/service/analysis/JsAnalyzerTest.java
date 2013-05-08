package pl.nask.hsn2.service.analysis;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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

public class JsAnalyzerTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(JsAnalyzerTest.class);
	private Set<String> whitelist;
	private String[] jsSourcesWhitelistTrue = { "alert(1+'-');", " alert ( \"1\" ) ; ", " alert \n\t\n\t  ('1');", "\nalert(1)\t;\n" };
	private String[] jsSourcesWhitelistFalse = { "alert(2);", "alertThis(\"1\");", "alert\n\t\n\t(1+2);", "\nalert('a');alert(1)\t;\n" };
	private final static String ALERT1_HASH = "f3312b1a03e36409470c404bd2f81e6f";
	
	// For malicious/suspicious tests
	private static final String JS_SOURCE_LONG = "Shell.Application ADODB.Stream WScript.Shell .exe .bat ms06 ms07 ms08 ms09 "
			+ "shellcode block heap spray exploit overflow savetofile .Exe .eXe .exE .EXe .eXE .ExE .EXE .Bat .bAt .baT .BAt "
			+ ".bAT .BaT top.location document.location window.location document.write document.writeln eval location.replace "
			+ "location.reload location.href document.body.innerhtml myTestMaliciousWordmyTestSuspiciousWord";
	private static final String JS_SOURCE_SHORT = ".exeeval";
	private static final String[] MALICIOUS_KEYWORDS = { "Shell.Application", "ADODB.Stream", "WScript.Shell", ".exe", ".bat", "ms06",
			"ms07", "ms08", "ms09", "shellcode", "block", "heap", "spray", "exploit", "overflow", "savetofile", ".Exe", ".eXe", ".exE",
			".EXe", ".eXE", ".ExE", ".EXE", ".Bat", ".bAt", ".baT", ".BAt", ".bAT", ".BaT", "myTestMaliciousWord" };
	private static final String[] SUSPICIOUS_KEYWORDS = { "top.location", "document.location", "window.location", "document.write",
			"document.writeln", "eval", "location.replace", "location.reload", "location.href", "document.body.innerhtml",
			"myTestSuspiciousWord" };

	@BeforeClass
	private void testInit() {
		whitelist = new HashSet<String>();
		whitelist.add(ALERT1_HASH);
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
			File f = IoTestsUtils.prepareTempFile(jsSourcesWhitelistTrue[i], JsAnalyzerTest.class.getSimpleName());

			JSContextResults result = analyzer.process(i, f);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistTrue[i]);
			Assert.assertTrue(isWhitelisted, "Should be whitelisted");
			
			Assert.assertEquals(result.getHash(), ALERT1_HASH);

			deleteTempFile(f);
		}
	}
	
	private void deleteTempFile(File f){
		try {
			Files.delete(f.toPath());
		} catch (IOException e) {
			LOGGER.warn("Could not delete temp file. (file={}, reason={})", f.getAbsolutePath(), e.getMessage());
		}
	}

	@Test
	public void whitelistFalseCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, whitelist);

		for (int i = 0; i < jsSourcesWhitelistFalse.length; i++) {
			// Prepare temp file.
			File f = IoTestsUtils.prepareTempFile(jsSourcesWhitelistFalse[i], JsAnalyzerTest.class.getSimpleName());

			JSContextResults result = analyzer.process(i, f);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistFalse[i]);
			Assert.assertFalse(isWhitelisted, "Should not be whitelisted");
			
			deleteTempFile(f);
		}
	}

	@Test()
	public void whitelistMd5ExceptionCheck() throws Exception {
		mockObjects();
		new NonStrictExpectations() {
			@Mocked
			MessageDigest md;
			{
				MessageDigest.getInstance("MD5");
				result = new NoSuchAlgorithmException();
			}
		};
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, whitelist);
		File f = IoTestsUtils.prepareTempFile(jsSourcesWhitelistTrue[0], JsAnalyzerTest.class.getSimpleName());
		JSContextResults result = analyzer.process(0, f);
		Assert.assertFalse(result.getWhitelisted(), "Should not be whitelisted.");
	}

	@Test
	public void maliciousSuspiciousLongCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(MALICIOUS_KEYWORDS, SUSPICIOUS_KEYWORDS, 0, 0, whitelist);

		// Prepare temp file.
		File f = IoTestsUtils.prepareTempFile(JS_SOURCE_LONG, JsAnalyzerTest.class.getSimpleName());
		JSContextResults result = analyzer.process(1, f);

		List<String> words = result.getMaliciousKeywordsList();
		for (String word : MALICIOUS_KEYWORDS) {
			Assert.assertTrue(words.contains(word), "Malicious word [" + word + "] not found in malicious list.");
			LOGGER.info("Found malicious word: {}", word);
		}
		words = result.getSuspiciousKeywordsList();
		for (String word : SUSPICIOUS_KEYWORDS) {
			Assert.assertTrue(words.contains(word), "Suspicious word [" + word + "] not found in malicious list.");
			LOGGER.info("Found suspicious word: {}", word);
		}

		deleteTempFile(f);
	}

	@Test
	public void maliciousSuspiciousShortCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(MALICIOUS_KEYWORDS, SUSPICIOUS_KEYWORDS, 0, 0, whitelist);

		// Prepare temp file.
		File f = IoTestsUtils.prepareTempFile(JS_SOURCE_SHORT, JsAnalyzerTest.class.getSimpleName());
		JSContextResults result = analyzer.process(1, f);

		List<String> words = result.getMaliciousKeywordsList();
		Assert.assertEquals(words.size(), 1);
		Assert.assertTrue(words.contains(".exe"));

		words = result.getSuspiciousKeywordsList();
		Assert.assertEquals(words.size(), 1);
		Assert.assertTrue(words.contains("eval"));

		deleteTempFile(f);
	}
}
