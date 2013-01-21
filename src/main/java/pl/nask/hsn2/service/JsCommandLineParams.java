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

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.nask.hsn2.CommandLineParams;

public class JsCommandLineParams extends CommandLineParams {
    private final static OptionNameWrapper TRAINING_SET = new OptionNameWrapper("ts", "trainingSet");
    private final static OptionNameWrapper CLASSIFIER_NAME = new OptionNameWrapper("cn", "classifierName");
    private final static OptionNameWrapper NGRAM_LENGHT = new OptionNameWrapper("nl", "ngramLength");
    private final static OptionNameWrapper NGRAM_QUANTITY = new OptionNameWrapper("nq", "ngramQuantity");
    private final static OptionNameWrapper LIB_PATH = new OptionNameWrapper("lib", "libPath");
    private final static OptionNameWrapper WHITELIST_PATH = new OptionNameWrapper("wp", "whitelistPath");
    private final static Logger LOGGER = LoggerFactory.getLogger(JsCommandLineParams.class);

	@Override
    public void initOptions() {
        super.initOptions();
        addOption(TRAINING_SET, "path", "Path to the ARFF file");
        addOption(CLASSIFIER_NAME, "name", "Parameter declares the name of classifier to be used by Weka Toolkit");
        addOption(NGRAM_LENGHT , "num", "Length of single ngram generated from the JavaScript source code.");
        addOption(NGRAM_QUANTITY, "num", "Path to the directory with the changes logged when processing URL");
        addOption(LIB_PATH, "path", "Path to the ngram lib file");
        addOption(WHITELIST_PATH, "path", "Path to whitelist files");
	}

	public String getTrainingSetName() {
		return getOptionValue(TRAINING_SET);
	}

	public String getWhitelistPath() {
		return getOptionValue(WHITELIST_PATH);
	}
	
	public String getClassifierName() {
		return getOptionValue(CLASSIFIER_NAME);
	}

	public int getNgramLength() {
		return getOptionIntValue(NGRAM_LENGHT);
	}

	public int getNgramQuantity() {
		return getOptionIntValue(NGRAM_QUANTITY);
	}

	@Override
	protected void initDefaults() {
	    super.initDefaults();
	    setDefaultValue(TRAINING_SET, "out4.arff");
	    setDefaultValue(WHITELIST_PATH, "whitelist");
	    setDefaultValue(CLASSIFIER_NAME, "weka.classifiers.bayes.NaiveBayes");
	    setDefaultIntValue(NGRAM_LENGHT, 4);
	    setDefaultIntValue(NGRAM_QUANTITY, 50);
	    setDefaultMaxThreads(1);
	    setDefaultServiceNameAndQueueName("js-sta");
	    setDefaultDataStoreAddress("http://127.0.0.1:8080");
	}

	public String getLibPath() {
		return getOptionValue(LIB_PATH);
	}

	@Override
	protected void validate(){
		super.validate();
		String msg = "";
		if (getClassifierName() == null){
			msg += "Classifier name not set!\n";
			LOGGER.error("Classifier name not set!");
		}
		if (!new File(getTrainingSetName()).exists()){
			msg += "TrainingSet file not exists!\n";
			LOGGER.error("TrainingSet file does not exist! Path used: {}", getTrainingSetName());
		}
		if (!new File(getWhitelistPath()).exists()){
			msg += "Whitelist file not exists!\n";
			LOGGER.error("Whitelist file does not exist! Path used: {}", getWhitelistPath());
		}
		if (!new File(getLibPath()).exists()){
			msg += "Lib file not exists!\n";
			LOGGER.error("Lib file does not exist! Path used: {}", getLibPath());
		}
		if (getNgramQuantity() <= 0){
			msg += "NgramQuantity must be greater than zero!\n";
			LOGGER.error("NgramQuantity must be greater than zero!");
		}
		if (getNgramLength() <= 0){
			msg += "NgramLength must be greater than zero!\n";
			LOGGER.error("NgramLength must be greater than zero!");
		}
		if (!msg.equals("")){
			throw new IllegalStateException(msg);
		}
	}
}
