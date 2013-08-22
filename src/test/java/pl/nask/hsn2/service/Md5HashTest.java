/*
 * Copyright (c) NASK, NCSC
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
import java.io.FileInputStream;
import java.io.InputStream;

import mockit.Delegate;
import mockit.Mocked;
import mockit.NonStrictExpectations;
import pl.nask.hsn2.ServiceConnector;
import pl.nask.hsn2.TaskContext;
import pl.nask.hsn2.connector.AMQP.OutConnector;
import pl.nask.hsn2.connector.REST.DataStoreConnectorImpl;
import pl.nask.hsn2.protobuff.Object.Attribute;
import pl.nask.hsn2.protobuff.Object.Attribute.Type;
import pl.nask.hsn2.protobuff.Object.ObjectData;
import pl.nask.hsn2.protobuff.Object.Reference;
import pl.nask.hsn2.service.analysis.JSWekaAnalyzer;
import pl.nask.hsn2.service.analysis.NGramsCalc;
import pl.nask.hsn2.utils.DataStoreHelper;
import pl.nask.hsn2.wrappers.ObjectDataWrapper;
import pl.nask.hsn2.wrappers.ParametersWrapper;

import com.rabbitmq.client.AMQP.Queue.DeclareOk;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.QueueingConsumer;

public class Md5HashTest {

	@Mocked
	Connection c;
	@Mocked
	Channel ch;
	@Mocked
	DeclareOk dok;
	@Mocked
	QueueingConsumer consumer;
	
	@Mocked("receive")
	OutConnector outC;
	
	//@Test
	@SuppressWarnings({ "static-access", "rawtypes", "unused"})
	public void processTest() throws Exception {

		new NonStrictExpectations() {
			@Mocked
			DataStoreConnectorImpl ds;
			
			@Mocked
			DataStoreHelper dsh;
			
			@Mocked
			JsCommandLineParams jsCMD;
			
			@Mocked("isMd5Check")
			JSWekaAnalyzer jsWA;
			
			{
				dsh.getFileAsInputStream(null, anyLong, anyLong);
				result = new Delegate() {
					private InputStream in;
					public InputStream getFileAsInputStream(ServiceConnector connector, long jobId, long referenceId) throws Exception{
						File f = new File("src/test/resources/" + referenceId);
						in = new FileInputStream(f);
						return in;
					}
				};
				
				jsCMD.getTrainingSetName();
				result = "out4.arff";
				
				jsCMD.getWhitelistPath();
				result = "whitelist.ssdeep";
				
				jsCMD.getClassifierName();
				result = "weka.classifiers.bayes.NaiveBayes";
				
				jsCMD.getNgramLength();
				result = 4;
				
				jsCMD.getNgramQuantity();
				result = 50;
			}
			
		};
		NGramsCalc.initialize("/home/rajdo/hsn/HSN2/trunk/software/Tools/hsn-ngrams/libngrams.so");
		
		long start = System.nanoTime();
		for(int j = 0; j < 10; j++){
			for(int i = 1; i < 5; i++) {
				Attribute.Builder attr = Attribute.newBuilder().setName("js_context_list").setType(Type.BYTES).setDataBytes(Reference.newBuilder().setKey(i).setStore(1));
				ObjectData objectData = ObjectData.newBuilder().setId(1).addAttrs(attr).build();
				JsAnalyzerTask analyzerTask = new JsAnalyzerTask(new TaskContext(2, 3, 4, null), new ParametersWrapper(), new ObjectDataWrapper(objectData) , new JsCommandLineParams());
//				System.out.println("ssdeep b " + (System.nanoTime() - start));
				analyzerTask.process();
//				System.out.println("ssdeep a " + (System.nanoTime() - start));
			}
		}
		System.out.println("ssdeep " + (System.nanoTime() - start));
	}
}
