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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import pl.nask.hsn2.ParameterException;
import pl.nask.hsn2.RequiredParameterMissingException;
import pl.nask.hsn2.ResourceException;
import pl.nask.hsn2.StorageException;
import pl.nask.hsn2.TaskContext;
import pl.nask.hsn2.protobuff.Resources.JSContext;
import pl.nask.hsn2.protobuff.Resources.JSContextList;
import pl.nask.hsn2.protobuff.Resources.JSContextResults;
import pl.nask.hsn2.service.analysis.JSWekaAnalyzer;
import pl.nask.hsn2.task.Task;
import pl.nask.hsn2.wrappers.ObjectDataWrapper;
import pl.nask.hsn2.wrappers.ParametersWrapper;

public class JsAnalyzerTask implements Task {

	private static final Logger LOGGER = LoggerFactory.getLogger(JsAnalyzerTask.class);
	private final TaskContext jobContext;

	private String maliciousKeywords = "Shell\\.Application|ADODB\\.Stream|WScript\\.Shell|\\.exe|\\.bat|ms0[6-9]|shellcode|block|heap|spray|exploit|overflow|savetofile";
	private String suspiciousKeywords = "top\\.location|document\\.location|window\\.location|document\\.write|document\\.writeln|eval|location\\.replace|location\\.reload|location\\.href|document\\.body\\.innerhtml|location=";
	private Long jsContextId;
	private JSWekaAnalyzer weka;
	private Set<String> whitelist;

	public JsAnalyzerTask(TaskContext jobContext, ParametersWrapper parameters, ObjectDataWrapper inputData, JsCommandLineParams cmd) throws IllegalStateException {
		this.jobContext = jobContext;
		jsContextId = inputData.getReferenceId("js_context_list");
		setParameters(parameters);
		prepareWhitelist(cmd.getWhitelistPath());
		weka = new JSWekaAnalyzer(maliciousKeywords, suspiciousKeywords, cmd.getNgramLength(), cmd.getNgramQuantity(), cmd.getLibPath(), whitelist);
		weka.prepare(cmd.getTrainingSetName(), cmd.getClassifierName());
	}

	private void prepareWhitelist(String whitelistPath) {
		FileReader fr = null;
		BufferedReader br = null;
		try {
			fr = new FileReader(whitelistPath);
			br = new BufferedReader(fr);
			String readLine;
			whitelist = new TreeSet<String>();
			while ((readLine = br.readLine()) != null) {
				readLine = readLine.trim();
				// MD5 hash hex string is always 32 characters length.
				if (readLine.length() == 32) {
					whitelist.add(readLine);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
			LOGGER.warn("Cannot access whitelist file.");
			LOGGER.debug(e.getMessage(), e);
		} finally {
			try {
				br.close();
				fr.close();
			} catch (IOException e) {
				LOGGER.warn("Cannot close whitelist buffered reader.");
				LOGGER.debug(e.getMessage(), e);
			}
		}
	}

	private void setParameters(ParametersWrapper parameters) {
		try {
			String mKeywords = parameters.get("keywords_malicious");
			if(mKeywords != null)
				maliciousKeywords = mKeywords;
		} catch (RequiredParameterMissingException e) {
			LOGGER.debug("Used default malicious keywords");
		}

		try {
			String sKeywords = parameters.get("keywords_suspicious");
			if(sKeywords != null)
				suspiciousKeywords = sKeywords;
		} catch (RequiredParameterMissingException e) {
			LOGGER.debug("Used default suspicious keywords");
		}

	}

	public boolean takesMuchTime() {
		return false;
	}

	@Override
	public void process() throws ParameterException, ResourceException,	StorageException {
		if(jsContextId != null){
			jobContext.addTimeAttribute("js_sta_time_begin", System.currentTimeMillis());

			try {
				JSContextList contextList = downloadJsContextList();

				ResultsBuilder resultsBuilder = new ResultsBuilder();

				for(JSContext context : contextList.getContextsList()){
					JSContextResults contextResults = weka.process(context);
					resultsBuilder.addResults(contextResults);
				}

				jobContext.addAttribute("js_classification", resultsBuilder.getClassificationAsString());
				jobContext.addAttribute("js_malicious_keywords", resultsBuilder.isMaliciousKeywords());
				jobContext.addAttribute("js_suspicious_keywords", resultsBuilder.isSuspiciousKeywords());
				long resultsId = jobContext.saveInDataStore(resultsBuilder.getJSStaticResultsAsBytes());
				jobContext.addReference("js_sta_results", resultsId);
				LOGGER.debug("Analysis end with: classif: {}, mkw: {}, skw: {}");
			} catch (IOException e) {
				LOGGER.error(e.getMessage(), e);
			}

			jobContext.addTimeAttribute("js_sta_time_end", System.currentTimeMillis());
		}
		else{
			LOGGER.info("Task skipped, not js");
		}
	}

	private JSContextList downloadJsContextList() throws StorageException, IOException{
		InputStream is = null;
		try{
			is = jobContext.getFileAsInputStream(jsContextId);
		return JSContextList.parseFrom(is);
		}
		finally{
			if(is != null){
				is.close();
			}
		}
	}

}
