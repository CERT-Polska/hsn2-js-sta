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
