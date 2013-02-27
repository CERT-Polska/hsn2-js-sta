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
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	private Set<String> whitelist;
	private final String[] maliciousWords;
	private final String[] suspiciousWords;

	public JSWekaAnalyzer(String[] maliciousKeywords, String[] suspiciousKeywords, int ngramsLength, int ngramsQuantity, String libPath,
			Set<String> whitelist) {
		this.ngramsLength = ngramsLength;
		this.ngramsQuantity = ngramsQuantity;
		this.whitelist = whitelist;
		this.maliciousWords = maliciousKeywords;
		this.suspiciousWords = suspiciousKeywords;
	}

	public JSContextResults process(int id, File jsSrcFile) throws IOException {
		JSContextResults.Builder resultsBuilder = JSContextResults.newBuilder().setId(id);

		// Check for malicious and suspicious keywords.
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(jsSrcFile));
		bis.mark(Integer.MAX_VALUE);
		addMaliciousAndSuspiciousKeywords(resultsBuilder, bis);

		// Calculate MD5 hash.
		String md5hash = md5hashFromFile(bis);
		bis.close();

		// Check is script is whitelisted.
		boolean isWhitelisted = whitelist.contains(md5hash);
		resultsBuilder.setWhitelisted(isWhitelisted);

		// Run weka check.
		JSClass jsClassify = classifyString(jsSrcFile);
		resultsBuilder.setClassification(jsClassify);

		return resultsBuilder.build();
	}

	private void addMaliciousAndSuspiciousKeywords(JSContextResults.Builder resultsBuilder, BufferedInputStream bufferedInputStream)
			throws IOException {
		// Results init.
		Set<String> maliciousWordsFound = new HashSet<>();
		Set<String> suspiciousWordsFound = new HashSet<>();

		// Find shortest and longest word.
		int shortestWordSize = Integer.MAX_VALUE;
		int longestWordSize = Integer.MIN_VALUE;
		int tempInt;
		for (String word : maliciousWords) {
			tempInt = word.length();
			if (tempInt < shortestWordSize) {
				shortestWordSize = tempInt;
			}
			if (tempInt > longestWordSize) {
				longestWordSize = tempInt;
			}
		}
		for (String word : suspiciousWords) {
			tempInt = word.length();
			if (tempInt < shortestWordSize) {
				shortestWordSize = tempInt;
			}
			if (tempInt > longestWordSize) {
				longestWordSize = tempInt;
			}
		}

		// We have to create buffer size of longest word.
		CircularStringBuffer circularBuffer = new CircularStringBuffer(longestWordSize);

		// Read full buffer.
		boolean isEofReached = false;
		for (tempInt = 0; tempInt < longestWordSize; tempInt++) {
			if (isEofReached = readOneChar(bufferedInputStream, circularBuffer)) {
				break;
			}
		}

		// Start searching.
		while (!isEofReached) {
			// Read one char into buffer.
			isEofReached = readOneChar(bufferedInputStream, circularBuffer);
			if (!isEofReached) {
				checkWords(circularBuffer, maliciousWordsFound, suspiciousWordsFound);
			}
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

	private void checkWords(CircularStringBuffer buffer, Set<String> maliciousWordsFound, Set<String> suspiciousWordsFound) {
		// Get string from buffer.
		String strToCheck = buffer.getAsString();

		// Search.
		for (String s : maliciousWords) {
			if (strToCheck.startsWith(s)) {
				maliciousWordsFound.add(s);
			}
		}
		for (String s : suspiciousWords) {
			if (strToCheck.startsWith(s)) {
				suspiciousWordsFound.add(s);
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
		InputStream dis = null;
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			dis = new DigestInputStream(new WhiteListFileInputStream(bufferedInputStream), md);
			while (dis.read() != -1) {
				// Nothing to do.
			}
			char[] md5 = Hex.encodeHex(md.digest());
			result = String.valueOf(md5);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Could not create MD5 hash for whitelisting.\n{}", e);
			result = "";
		} finally {
			if (dis != null) {
				dis.close();
			}
		}
		return result;
	}
}
