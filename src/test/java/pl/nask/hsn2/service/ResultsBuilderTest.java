package pl.nask.hsn2.service;

import java.util.ArrayList;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.Test;

import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.Builder;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;
import pl.nask.hsn2.protobuff.Resources.JSStaticResults;

public class ResultsBuilderTest {
	private static final String TEST_HASH = "098f6bcd4621d373cade4e832627b4f6";

	@Test
	public void buildTest() throws Exception {
		ResultsBuilder rb = new ResultsBuilder();
		Builder contextResultsBuilder = JSContextResults.newBuilder().setId(1).setClassification(JSClass.UNCLASSIFIED)
				.setWhitelisted(false);
		List<String> wordsListMal = new ArrayList<>();
		wordsListMal.add("word1");
		wordsListMal.add("word2");
		wordsListMal.add("word3");
		contextResultsBuilder.addAllMaliciousKeywords(wordsListMal);
		List<String> wordsListSus = new ArrayList<>();
		wordsListSus.add("word11");
		wordsListSus.add("word21");
		wordsListSus.add("word31");
		contextResultsBuilder.addAllSuspiciousKeywords(wordsListSus);
		contextResultsBuilder.setHash(TEST_HASH);
		rb.addResults(contextResultsBuilder.build());
		contextResultsBuilder = JSContextResults.newBuilder()
				.setId(2)
				.setClassification(JSClass.BENIGN)
				.setWhitelisted(false)
				.setHash(TEST_HASH);;
		rb.addResults(contextResultsBuilder.build());
		contextResultsBuilder = JSContextResults.newBuilder()
				.setId(3)
				.setClassification(JSClass.OBFUSCATED)
				.setWhitelisted(false)
				.setHash(TEST_HASH);
		rb.addResults(contextResultsBuilder.build());
		contextResultsBuilder = JSContextResults.newBuilder()
				.setId(4)
				.setClassification(JSClass.MALICIOUS)
				.setWhitelisted(false)
				.setHash(TEST_HASH);
		rb.addResults(contextResultsBuilder.build());

		Assert.assertEquals(rb.getClassification(), JSClass.MALICIOUS);
		Assert.assertEquals(rb.isMaliciousKeywords(), true);
		Assert.assertEquals(rb.isSuspiciousKeywords(), true);
		Assert.assertEquals(rb.getJSStaticResults().getResults(2).getClassification(), JSClass.OBFUSCATED);
		Assert.assertEquals(rb.getClassificationAsString(), "malicious");

		byte[] byteArr = rb.getJSStaticResultsAsBytes();
		JSStaticResults sr = JSStaticResults.parseFrom(byteArr);
		Assert.assertEquals(sr.getResults(2).getClassification(), JSClass.OBFUSCATED);
	}
}
