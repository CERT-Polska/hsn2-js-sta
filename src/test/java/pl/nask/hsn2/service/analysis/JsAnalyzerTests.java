package pl.nask.hsn2.service.analysis;

import java.util.HashSet;
import java.util.Set;

import mockit.Mocked;
import mockit.NonStrictExpectations;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import pl.nask.hsn2.protobuff.Resources.JSContext;
import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;

public class JsAnalyzerTests {
	private static final Logger LOGGER = LoggerFactory.getLogger(JsAnalyzerTests.class);
	private Set<String> whitelist;
	private String[] jsSourcesWhitelistTrue = { "alert(1+'-');", " alert ( \"1\" ) ; ", " alert \n\t\n\t  ('1');", "\nalert(1)\t;\n" };
	private String[] jsSourcesWhitelistFalse = { "alert(2);", "alertThis(\"1\");", "alert\n\t\n\t(1+2);", "\nalert('a');alert(1)\t;\n" };

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
				analyzer.classifyString(anyString);
				result = JSClass.UNCLASSIFIED;
			}
		};
	}

	@Test
	public void whitelistTrueCheck() throws Exception {
		mockObjects();

		// create analyzer
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer("", "", 0, 0, "", whitelist);

		for (int i = 0; i < jsSourcesWhitelistTrue.length; i++) {
			// javascript context
			boolean jsctxEval = false;
			int jsctxId = 1;
			JSContext jsctx = JSContext.newBuilder().setEval(jsctxEval).setId(jsctxId).setSource(jsSourcesWhitelistTrue[i]).build();

			// test
			JSContextResults result = analyzer.process(jsctx);
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
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer("", "", 0, 0, "", whitelist);

		for (int i = 0; i < jsSourcesWhitelistFalse.length; i++) {
			// javascript context
			boolean jsctxEval = false;
			int jsctxId = 1;
			JSContext jsctx = JSContext.newBuilder().setEval(jsctxEval).setId(jsctxId).setSource(jsSourcesWhitelistFalse[i]).build();

			// test
			JSContextResults result = analyzer.process(jsctx);
			boolean isWhitelisted = result.getWhitelisted();
			LOGGER.info("Source[{}] whitelisted? {}", i, isWhitelisted);
			LOGGER.info("Source[{}]:\n{}", i, jsSourcesWhitelistFalse[i]);
			Assert.assertFalse(isWhitelisted, "Should not be whitelisted");
		}
	}
}
