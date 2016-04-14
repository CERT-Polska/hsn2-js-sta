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

import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;
import pl.nask.hsn2.protobuff.Resources.JSStaticResults;

public class ResultsBuilder {
	private static final int MALICIOUS_ID = 3;
	private List<JSContextResults> resultsList = new ArrayList<JSContextResults>();
	private boolean maliciousKeywords = false;
	private boolean suspiciousKeywords = false;
	private JSClass classification = JSClass.UNCLASSIFIED;

	public final void addResults(JSContextResults contextResults) {
		resultsList.add(contextResults);
		setKeywordsFlag(contextResults);
		updateClassification(contextResults);
	}

	private void setKeywordsFlag(JSContextResults contextResults) {
		maliciousKeywords = maliciousKeywords || contextResults.getMaliciousKeywordsCount() > 0;
		suspiciousKeywords = suspiciousKeywords || contextResults.getSuspiciousKeywordsCount() > 0;
	}

	private void updateClassification(JSContextResults contextResults) {
		JSClass newClassification = contextResults.getClassification();
		boolean isWhitelisted = contextResults.getWhitelisted();
		if (!isWhitelisted && order(classification) < order(newClassification)) {
			classification = newClassification;
		}
	}

	private int order(JSClass jsclass) {
		// unclassified < benign < obfuscated < malicious
		switch (jsclass) {
		case UNCLASSIFIED:
			return 0;
		case BENIGN:
			return 1;
		case OBFUSCATED:
			return 2;
		case MALICIOUS:
			return MALICIOUS_ID;
		default:
			throw new IllegalArgumentException("Unknown JSClass: " + jsclass);
		}
	}

	public final JSStaticResults getJSStaticResults() {
		return JSStaticResults.newBuilder().addAllResults(resultsList).build();
	}

	public final boolean isMaliciousKeywords() {
		return maliciousKeywords;
	}

	public final boolean isSuspiciousKeywords() {
		return suspiciousKeywords;
	}

	public final JSClass getClassification() {
		return classification;
	}

	public final String getClassificationAsString() {
		return classification.name().toLowerCase();
	}

	public final byte[] getJSStaticResultsAsBytes() {
		return getJSStaticResults().toByteArray();
	}
}
