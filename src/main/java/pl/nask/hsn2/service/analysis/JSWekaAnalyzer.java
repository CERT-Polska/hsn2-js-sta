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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.Builder;
import pl.nask.hsn2.protobuff.Resources.JSContextResults.JSClass;
import pl.nask.hsn2.service.SSDeepHash;
import weka.classifiers.Classifier;
import weka.classifiers.meta.FilteredClassifier;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ConverterUtils;
import weka.filters.unsupervised.attribute.StringToWordVector;

public class JSWekaAnalyzer {

	private static final Logger LOGGER = LoggerFactory.getLogger(JSWekaAnalyzer.class);
	private static final int MAX_SIMILARITY_FACTOR = 100;
	private static FilteredClassifier fc = null;
	private static Instances trainingSet = null;
	private int ngramsLength;
	private int ngramsQuantity;
	private List<SSDeepHash> whitelist;
	private final String[] maliciousWords;
	private final String[] suspiciousWords;
	private int shortestWordSize = Integer.MAX_VALUE;
	private int longestWordSize = Integer.MIN_VALUE;
	private SSDeepHashGenerator generator;

	public JSWekaAnalyzer(String[] maliciousKeywords, String[] suspiciousKeywords, int ngramsLength, int ngramsQuantity,
			List<SSDeepHash> whitelist) {
		this.ngramsLength = ngramsLength;
		this.ngramsQuantity = ngramsQuantity;
		this.whitelist = whitelist;
		this.maliciousWords = maliciousKeywords.clone();
		this.suspiciousWords = suspiciousKeywords.clone();
		generator = new SSDeepHashGenerator();
	}

	public JSContextResults process(int id, File jsSrcFile) throws IOException {
		Builder resultsBuilder = JSContextResults.newBuilder().setId(id);

		// Check for malicious and suspicious keywords.
		try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(jsSrcFile), 50000)) {
			bis.mark(Integer.MAX_VALUE);
			addMaliciousAndSuspiciousKeywords(resultsBuilder, bis);

			checkSsdeepHashAndUpdateResults(jsSrcFile.getAbsolutePath(), resultsBuilder);
		}

		// Run weka check.
		JSClass jsClassify = classifyString(jsSrcFile);
		resultsBuilder.setClassification(jsClassify);

		return resultsBuilder.build();
	}
	
	private void checkSsdeepHashAndUpdateResults(String absolutePath, Builder resultsBuilder) {
		String hash = generator.generateHashForFile(absolutePath);
		resultsBuilder.setHash(hash);
		for(SSDeepHash ssdeepHash : whitelist) {
			if(ssdeepHash.getMatch() < MAX_SIMILARITY_FACTOR){
				int score = generator.compare(ssdeepHash.getHash(), hash);
				if (score >= ssdeepHash.getMatch()) {
					resultsBuilder.setWhitelisted(true);
					return;
				}
			}
			else if(ssdeepHash.getMatch() == MAX_SIMILARITY_FACTOR && ssdeepHash.getHash().equals(hash)){
				resultsBuilder.setWhitelisted(true);
				return;
			}
			else{
				LOGGER.warn("The similarity factor is greater then 100: " + ssdeepHash.getMatch());
			}
		}
		resultsBuilder.setWhitelisted(false);
	}

	private void updateLongestAndShortestWordSize(String[] words) {
		int tempInt;
		for (String word : words) {
			tempInt = word.length();
			if (tempInt < shortestWordSize) {
				shortestWordSize = tempInt;
			}
			if (tempInt > longestWordSize) {
				longestWordSize = tempInt;
			}
		}
	}

	private void addMaliciousAndSuspiciousKeywords(JSContextResults.Builder resultsBuilder, BufferedInputStream bufferedInputStream)
			throws IOException {
		// Find shortest and longest word.
		shortestWordSize = Integer.MAX_VALUE;
		longestWordSize = Integer.MIN_VALUE;
		updateLongestAndShortestWordSize(maliciousWords);
		updateLongestAndShortestWordSize(suspiciousWords);

		// We have to create buffer size of longest word.
		CircularStringBuffer circularBuffer = new CircularStringBuffer(longestWordSize);

		// Read full buffer.
		int tempInt;
		for (tempInt = 0; tempInt < longestWordSize - 1; tempInt++) {
			if (readOneChar(bufferedInputStream, circularBuffer)) {
				break;
			}
		}

		// Start searching.
		Set<String> maliciousWordsFound = new HashSet<>();
		Set<String> suspiciousWordsFound = new HashSet<>();
		while (!readOneChar(bufferedInputStream, circularBuffer)) {
			checkWords(circularBuffer, maliciousWordsFound, suspiciousWordsFound);
		}

		// EOF reach but we have not finished yet.
		for (tempInt = shortestWordSize; tempInt < longestWordSize; tempInt++) {
			circularBuffer.add(' ');
			checkWords(circularBuffer, maliciousWordsFound, suspiciousWordsFound);
		}

		// Store results.
		resultsBuilder.addAllMaliciousKeywords(maliciousWordsFound);
		resultsBuilder.addAllSuspiciousKeywords(suspiciousWordsFound);
	}

	/**
	 * Checks if there are any malicious or suspicious words in buffer.
	 * 
	 * @param circularBuffer
	 *            Buffer to read from.
	 * @param maliciousResults
	 *            Set to store malicious words found.
	 * @param suspiciousResults
	 *            Set to store suspicious words found.
	 */
	private void checkWords(CircularStringBuffer circularBuffer, Set<String> maliciousResults, Set<String> suspiciousResults) {
		String word = circularBuffer.getAsString();
		checkWord(word, maliciousWords, maliciousResults);
		checkWord(word, suspiciousWords, suspiciousResults);
	}

	/**
	 * Reads one character from file and adds to buffer. Returns true if EOF hit.
	 * 
	 * @param stream
	 * @param buffer
	 * @return Returns true if EOF hit, false otherwise.
	 * @throws IOException
	 */
	private boolean readOneChar(InputStream stream, CircularStringBuffer buffer) throws IOException {
		boolean eof = false;
		int chInt = stream.read();
		if (chInt == -1) {
			eof = true;
		} else {
			buffer.add((char) chInt);
		}
		return eof;
	}

	/**
	 * Checks if pattern contains given word and if it is, adds it to result set.
	 * 
	 * @param word
	 * @param pattern
	 * @param results
	 */
	private void checkWord(String word, String[] pattern, Set<String> results) {
		// Search.
		for (String s : pattern) {
			if (word.startsWith(s)) {
				results.add(s);
			}
		}
	}

	public JSClass classifyString(File file) {
		String ngrams = NGramsCalc.getNgramsForFile(file.getPath(), ngramsLength, ngramsQuantity);

		if (ngrams == null) {
			LOGGER.info("No ngrams extracted, probably JS source is too short");
		} else {
			StringTokenizer st = new StringTokenizer(ngrams, " ");
			if (st.countTokens() >= ngramsQuantity) {

				Instance t = new Instance(2);
				t.setDataset(trainingSet);
				t.setValue(0, ngrams);

				try {
					double dd = fc.classifyInstance(t);
					return JSClass.valueOf(trainingSet.classAttribute().value((int) dd).toUpperCase());
				} catch (Exception e) {
					LOGGER.error(e.getMessage(), e);
				}
			}
		}
		return JSClass.UNCLASSIFIED;
	}

	private void createTrainingSet(String arffFileName, String classifierName) {
		try {
			ConverterUtils.DataSource source = new ConverterUtils.DataSource(arffFileName);
			Instances trainingSetTemp = source.getDataSet();
			if (trainingSetTemp.classIndex() == -1) {
				trainingSetTemp.setClassIndex(trainingSetTemp.numAttributes() - 1);
			}
			Classifier naiveBayes = (Classifier) Class.forName(classifierName).newInstance();
			FilteredClassifier filteredClassifier = new FilteredClassifier();
			filteredClassifier.setClassifier(naiveBayes);
			filteredClassifier.setFilter(new StringToWordVector());
			filteredClassifier.buildClassifier(trainingSetTemp);
			JSWekaAnalyzer.trainingSet = trainingSetTemp;
			JSWekaAnalyzer.fc = filteredClassifier;
		} catch (Exception e) {
			LOGGER.error(e.getMessage(), e);
			JSWekaAnalyzer.fc = null;
		}
	}

	public void prepare(String arffFileName, String classifierName) {
		if (trainingSet == null) {
			createTrainingSet(arffFileName, classifierName);
		}
	}

	/**
	 * Returns hex string representation of MD5 hash for given file.
	 * 
	 * @param fileName
	 * @return
	 * @throws IOException
	 */
	public String md5hashFromFile(BufferedInputStream bufferedInputStream) throws IOException {
		bufferedInputStream.reset();
		String result = null;
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("MD5");
			md.reset();
			try (InputStream dis = new DigestInputStream(new WhiteListFileInputStream(bufferedInputStream), md)) {
				while (dis.read() != -1) {
					// Nothing to do.
				}
				char[] md5 = Hex.encodeHex(md.digest());
				result = String.valueOf(md5);
			}
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Could not create MD5 hash for whitelisting.\n{}", e);
			result = "";
		}
		return result;
	}
}
