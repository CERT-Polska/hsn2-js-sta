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

package pl.nask.hsn2.service.analysis;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.nask.hsn2.protobuff.Resources.JSContext;
import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;
import weka.classifiers.Classifier;
import weka.classifiers.meta.FilteredClassifier;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ConverterUtils;
import weka.filters.unsupervised.attribute.StringToWordVector;


public class JSWekaAnalyzer {

	private static final Logger LOGGER = LoggerFactory.getLogger(JSWekaAnalyzer.class);
    private static FilteredClassifier fc = null;
    private static Instances trainingSet = null;
    private int ngramsLength;
    private int ngramsQuantity;
    private Pattern maliciousKeywords;
    private Pattern suspiciousKeywords;
    private Set<String> whitelist;

    public JSWekaAnalyzer(String maliciousKeywords, String suspiciousKeywords, int ngramsLength, int ngramsQuantity, String libPath, Set<String> whitelist) {
		this.maliciousKeywords = Pattern.compile(maliciousKeywords, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
		this.suspiciousKeywords = Pattern.compile(suspiciousKeywords, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
		this.ngramsLength = ngramsLength;
		this.ngramsQuantity = ngramsQuantity;
		this.whitelist = whitelist;
	}

	public JSContextResults process(JSContext context) {
		JSContextResults.Builder resultsBuilder = JSContextResults.newBuilder().setId(context.getId());
		String jsSource = context.getSource();

		resultsBuilder.addAllMaliciousKeywords(matchKeywords(maliciousKeywords.matcher(jsSource)));
		resultsBuilder.addAllSuspiciousKeywords(matchKeywords(suspiciousKeywords.matcher(jsSource)));

		JSClass jsClassify = classifyString(jsSource);
		resultsBuilder.setClassification(jsClassify);

		String md5hash = md5hash(jsSource);
		boolean isWhitelisted = whitelist.contains(md5hash);
		resultsBuilder.setWhitelisted(isWhitelisted);

		return resultsBuilder.build();
	}

	private Set<String> matchKeywords(Matcher matcher){
		Set<String> keywords = new HashSet<String>();
		while (matcher.find()){
        	keywords.add(matcher.group(0));
		}
		return keywords;
	}

    public JSClass classifyString(String testJS) {
    	if (testJS == null) {
        	LOGGER.error("test string is null");
        }
        else {
	        String ngrams = NGramsCalc.getNgramsForString(testJS, ngramsLength, ngramsQuantity);

	        if (ngrams == null){
	        	LOGGER.info("No ngrams extracted, probably js is too short: {} characters.", testJS.length());
	        }
	        else{

		        StringTokenizer st = new StringTokenizer(ngrams, " ");
		        if (st.countTokens() >= ngramsQuantity) {

		        	Instance t = new Instance(2);
			        t.setDataset(trainingSet);
			        t.setValue(0, ngrams);

			        try {
			            double dd = fc.classifyInstance(t);
			            return JSClass.valueOf(trainingSet.classAttribute().value((int) dd).toUpperCase());
			        } catch (Exception e) {
			        	LOGGER.error(e.getMessage(),e);
			        }
		        }
	        }
        }
        return JSClass.UNCLASSIFIED;
    }

    private void createTrainingSet(String arffFileName, String classifierName) {
        try {
            ConverterUtils.DataSource source = new ConverterUtils.DataSource(arffFileName);
            Instances trainingSet = source.getDataSet();
            if (trainingSet.classIndex() == -1) {
                trainingSet.setClassIndex(trainingSet.numAttributes() - 1);
            }

            Classifier naiveBayes = (Classifier) Class.forName(classifierName).newInstance();


            FilteredClassifier fc = new FilteredClassifier();
            fc.setClassifier(naiveBayes);
            fc.setFilter(new StringToWordVector());

            fc.buildClassifier(trainingSet);
            JSWekaAnalyzer.trainingSet = trainingSet;
            JSWekaAnalyzer.fc = fc;
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            JSWekaAnalyzer.fc = null;
        }
    }

    public void prepare(String arffFileName, String classifierName) throws IllegalStateException {
        if (trainingSet == null){
	        createTrainingSet(arffFileName, classifierName);
        }
    }

	/**
	 * Returns javascript trimmed only to digits and letters [0-9A-Za-z].
	 * 
	 * @param input
	 *            Javascript source.
	 * @return Trimmed source.
	 */
	private String jsSourceTrimmed(String input) {
		if (input != null) {
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < input.length(); i++) {
				char ch = input.charAt(i);
				if (isCharAccepted(ch)) {
					sb.append(ch);
				}
			}
			return sb.toString();
		} else {
			return "";
		}
	}

	/**
	 * Checks if character is accepted in trimmed javascript source.
	 * 
	 * @param ch
	 * @return True if character has been accepted and should be present in trimmed string, otherwise false.
	 */
	private boolean isCharAccepted(char ch) {
		if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Returns hex string representation of MD5 hash for given string.
	 * 
	 * @param jsSource
	 * @return
	 */
	private String md5hash(String jsSource) {
		jsSource = jsSourceTrimmed(jsSource);
		try {
			byte[] byteHash = MessageDigest.getInstance("MD5").digest(jsSource.getBytes());
			String stringHash = new String(Hex.encodeHex(byteHash));
			return stringHash;
		} catch (NoSuchAlgorithmException e) {
			return "";
		}
	}
}
