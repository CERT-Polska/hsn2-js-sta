package pl.nask.hsn2.service.analysis;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import mockit.Mocked;
import mockit.NonStrictExpectations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;
import pl.nask.hsn2.service.SSDeepHash;

public class JsAnalyzerTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(JsAnalyzerTest.class);
	private List<SSDeepHash> whitelist;
//	private String[] jsSourcesWhitelistTrue = { "alert(1+'-');", " alert ( \"1\" ) ; ", " alert \n\t\n\t  ('1');", "\nalert(1)\t;\n" };
//	private String[] jsSourcesWhitelistFalse = { "alert(2);", "alertThis(\"1\");", "alert\n\t\n\t(1+2);", "\nalert('a');alert(1)\t;\n" };
	private final static SSDeepHash WHITELISTED_HASH = new SSDeepHash(70, "6:7wt8yYmBFUMIchgMu24Rljb7J4ixHdlu7u7X7u/qu/BLzdHxKm+1BX3x2j2QW7Z:7GYE/947buitLEqwBLxHsdBXh2CQW7Z");
	
	private static final String JS_SOURCE_LONG = "Shell.Application ADODB.Stream WScript.Shell .exe .bat ms06 ms07 ms08 ms09 "
			+ "shellcode block heap spray exploit overflow savetofile .Exe .eXe .exE .EXe .eXE .ExE .EXE .Bat .bAt .baT .BAt "
			+ ".bAT .BaT top.location document.location window.location document.write document.writeln eval location.replace "
			+ "location.reload location.href document.body.innerhtml myTestMaliciousWordmyTestSuspiciousWord";
	
	private static final String JS_SOURCE_LONG_SIMILAR = "Shell.Application ADODB.Stream WScript.Shell .exe .bat ms06 ms07 ms08 ms09 "
			+ "shellcode block .EXE .Bat .bAt .baT .BAt "
			+ ".bAT .BaT top.location document.write document.writeln eval location.replace "
			+ "location.reload myTestMaliciousWordmyTestSuspiciousWord";
	
	private static final String JS_SOURCE_LONG_DIFFERENT = "analyzer.classifyString(withInstanceOf(File.class)); "
			+ "analyzer.classifyString(withInstanceOf(File.class)); analyzer.classifyString(withInstanceOf(File.class)); "
			+ "analyzer.classifyString(withInstanceOf(File.class)); analyzer.classifyString(withInstanceOf(File.class)); "
			+ "analyzer.classifyString(withInstanceOf(File.class)); analyzer.classifyString(withInstanceOf(File.class));";
	
	
	private static final String JS_SOURCE_SHORT = ".exeeval";
	private static final String[] MALICIOUS_KEYWORDS = { "Shell.Application", "ADODB.Stream", "WScript.Shell", ".exe", ".bat", "ms06",
			"ms07", "ms08", "ms09", "shellcode", "block", "heap", "spray", "exploit", "overflow", "savetofile", ".Exe", ".eXe", ".exE",
			".EXe", ".eXE", ".ExE", ".EXE", ".Bat", ".bAt", ".baT", ".BAt", ".bAT", ".BaT", "myTestMaliciousWord" };
	private static final String[] SUSPICIOUS_KEYWORDS = { "top.location", "document.location", "window.location", "document.write",
			"document.writeln", "eval", "location.replace", "location.reload", "location.href", "document.body.innerhtml",
			"myTestSuspiciousWord" };

	@BeforeClass
	private void testInit() {
		whitelist = new ArrayList<SSDeepHash>();
		whitelist.add(WHITELISTED_HASH);
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

			// Prepare temp file.
			File f = IoTestsUtils.prepareTempFile(JS_SOURCE_LONG, JsAnalyzerTest.class.getSimpleName());

			JSContextResults result = analyzer.process(1, f);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", 1, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", 1, JS_SOURCE_LONG);
			Assert.assertTrue(isWhitelisted, "Should be whitelisted");
			
			deleteTempFile(f);
	}
	
	@Test
	public void whitelistTrueCheckForSimilar() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(new String[] { "" }, new String[] { "" }, 0, 0, whitelist);

			// Prepare temp file.
			File f = IoTestsUtils.prepareTempFile(JS_SOURCE_LONG_SIMILAR, JsAnalyzerTest.class.getSimpleName());

			JSContextResults result = analyzer.process(1, f);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", 1, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", 1, JS_SOURCE_LONG_SIMILAR);
			Assert.assertTrue(isWhitelisted, "Should be whitelisted");
			
			deleteTempFile(f);
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

		// Prepare temp file.
		File f = IoTestsUtils.prepareTempFile(JS_SOURCE_LONG_DIFFERENT, JsAnalyzerTest.class.getSimpleName());

		JSContextResults result = analyzer.process(1, f);
		boolean isWhitelisted = result.getWhitelisted();
		LOGGER.info("Source[{}] whitelisted? {}", 1, isWhitelisted);
		LOGGER.info("Source[{}]:\n{}", 1, JS_SOURCE_LONG_DIFFERENT);
		Assert.assertFalse(isWhitelisted, "Should not be whitelisted");
		
		deleteTempFile(f);
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
