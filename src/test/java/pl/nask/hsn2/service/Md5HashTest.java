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
import java.io.FileNotFoundException;
import java.io.InputStream;

import mockit.Delegate;
import mockit.Injectable;
import mockit.Mocked;
import mockit.NonStrictExpectations;

import org.omg.CORBA.portable.Streamable;
import org.testng.annotations.Test;

import pl.nask.hsn2.FinishedJobsListener;
import pl.nask.hsn2.GenericCmdParams;
import pl.nask.hsn2.ParameterException;
import pl.nask.hsn2.ResourceException;
import pl.nask.hsn2.ServiceConnector;
import pl.nask.hsn2.StorageException;
import pl.nask.hsn2.TaskContext;
import pl.nask.hsn2.connector.AMQP.OutConnector;
import pl.nask.hsn2.connector.REST.DataStoreConnectorImpl;
import pl.nask.hsn2.protobuff.Jobs.JobFinished;
import pl.nask.hsn2.protobuff.Jobs.JobFinishedReminder;
import pl.nask.hsn2.protobuff.Jobs.JobStatus;
import pl.nask.hsn2.protobuff.Object.Attribute;
import pl.nask.hsn2.protobuff.Object.ObjectData;
import pl.nask.hsn2.protobuff.Object.Reference;
import pl.nask.hsn2.protobuff.Object.Attribute.Type;
import pl.nask.hsn2.protobuff.ObjectStore.ObjectResponse;
import pl.nask.hsn2.protobuff.ObjectStore.ObjectResponse.ResponseType;
import pl.nask.hsn2.protobuff.Process.TaskRequest;
import pl.nask.hsn2.service.analysis.JSWekaAnalyzer;
import pl.nask.hsn2.service.analysis.NGramsCalc;
import pl.nask.hsn2.utils.DataStoreHelper;
import pl.nask.hsn2.wrappers.ObjectDataWrapper;
import pl.nask.hsn2.wrappers.ParametersWrapper;

import com.rabbitmq.client.AMQP.BasicProperties;
import com.rabbitmq.client.AMQP.Queue.DeclareOk;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Envelope;
import com.rabbitmq.client.QueueingConsumer;
import com.rabbitmq.client.QueueingConsumer.Delivery;

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
	
	@SuppressWarnings({ "rawtypes", "unused" })
	private void mockObjects() throws Exception {
		new NonStrictExpectations() {
			boolean task = true;
			
			@Mocked
			FinishedJobsListener jbl;
			
			@Mocked
			DataStoreHelper dsh;
			
			@Mocked
			ConnectionFactory cf;
			{
				// Create new connection.
				cf.newConnection();
				result = c;

				// Create channel.
				c.createChannel();
				result = ch;

				// Close connection.
				c.close();

				// Declare exchange.
				ch.exchangeDeclare(anyString, anyString);

				// Declare queue.
				ch.queueDeclare();
				result = dok;

				// Get queue name.
				dok.getQueue();
				
				jbl.isJobFinished(anyLong);
				result = false;

				consumer.nextDelivery();
				result = new Delegate() {
					public Delivery nextDelivery() throws Exception {
						Thread.sleep(100);
						Delivery d = null;
						if (task) {
							d = taskRequestMsg();						
							task = false;
						}
						else{
							d = objectResponseMsg();
							task = true;
						}
						return d;
					}
					
					private Delivery taskRequestMsg() {
						Envelope envelope = new Envelope(1, false, "", "");
						BasicProperties properties = new BasicProperties.Builder().type("TaskRequest").contentType("application/hsn2+protobuf").build();
						
						TaskRequest tr = TaskRequest.newBuilder().setTaskId(1).setJob(1).setObject(1).build();
						byte[] body = tr.toByteArray();
						Delivery d = new Delivery(envelope, properties, body);
						return d;
					}

					private Delivery objectResponseMsg() {
						
						Envelope envelope = new Envelope(1, false, "", "");
						BasicProperties properties = new BasicProperties.Builder().type("TaskRequest").contentType("application/hsn2+protobuf").build();
						
						ObjectData.Builder data = ObjectData.newBuilder().setId(anyLong);
						ObjectResponse or = ObjectResponse.newBuilder().setType(ResponseType.SUCCESS_GET).addData(data).build();
						byte[] body = or.toByteArray();
						Delivery d = new Delivery(envelope, properties, body);
						return d;
					}
				};
				
				outC.receive();
				result = new Delegate() {
					public byte[] receive(){
						Attribute.Builder attr = Attribute.newBuilder().setName("js_context_list").setType(Type.BYTES).setDataBytes(Reference.newBuilder().setKey(1).setStore(1));
						ObjectData.Builder data = ObjectData.newBuilder().setId(anyLong).addAttrs(attr);
						ObjectResponse or = ObjectResponse.newBuilder().setType(ResponseType.SUCCESS_GET).addData(data).build();
						byte[] body = or.toByteArray();
						return body;
					}
				};
				
				
			}
		};
	}
	
	private void mockDataStore() throws ResourceException, StorageException{
		new NonStrictExpectations() {
			
		};
	}
	
	//@Test
	public void oneHundredRunsTest() throws Exception{
		long start = System.nanoTime();
		
		mockObjects();
		mockDataStore();
		JsAnalyzerService.main(new String[]{"-svQueueName", "srv-js-sta:l", "-dataStore", "http://127.0.0.1:8080", "-libPath", "/home/rajdo/hsn/HSN2/trunk/software/Tools/hsn-ngrams/libngrams.so", "-maxThreads", "1", "-lf", "log.log", "-ll", "DEBUG"});
		for(int i = 0; i < 5; i++) {
			
		}
		Thread.sleep(60000);
		System.out.println(System.nanoTime() - start);
	}
	
	
	
	//@Test
	public void processTest() throws Exception {

		new NonStrictExpectations() {
			@Mocked
			DataStoreConnectorImpl ds;
			
			@Mocked
			DataStoreHelper dsh;
			
			@Mocked
			JsCommandLineParams jsCMD;
//			@Mocked
//			GenericCmdParams cmd;
			
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
				

				jsWA.isMd5Check();
				result = false;
//				jsCMD.parseParams(new String[]{});
//				result = new Delegate() {
//					private InputStream in;
//					public void parseParams(String[] cmd) throws Exception{
//						jsCMD.initDefaults();
//					}					
//				};
//				
//				cmd.getOptionValue(anyString);
//				result = new Delegate() {
//					protected final String getOptionValue(String optionName) {
//						return getDefaultValue(optionName);
//					}
//				};
				
			}
			
		};
		NGramsCalc.initialize("/home/rajdo/hsn/HSN2/trunk/software/Tools/hsn-ngrams/libngrams.so");
		
		long start = System.nanoTime();
		for(int j = 0; j < 10; j++){
			for(int i = 1; i < 4; i++) {
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
	
	//@Test
	public void processTest1() throws Exception {

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
				result = "whitelist.md5";
				
				jsCMD.getClassifierName();
				result = "weka.classifiers.bayes.NaiveBayes";
				
				jsCMD.getNgramLength();
				result = 4;
				
				jsCMD.getNgramQuantity();
				result = 50;
				
				jsWA.isMd5Check();
				result = true;
				
//				jsCMD.parseParams(new String[]{});
//				result = new Delegate() {
//					private InputStream in;
//					public void parseParams(String[] cmd) throws Exception{
//						jsCMD.initDefaults();
//					}					
//				};
//				
//				cmd.getOptionValue(anyString);
//				result = new Delegate() {
//					protected final String getOptionValue(String optionName) {
//						return getDefaultValue(optionName);
//					}
//				};
				
			}
			
		};
		NGramsCalc.initialize("/home/rajdo/hsn/HSN2/trunk/software/Tools/hsn-ngrams/libngrams.so");
		
		long start = System.nanoTime();
		for(int j = 0; j < 10; j++){
			for(int i = 1; i < 4; i++) {
				Attribute.Builder attr = Attribute.newBuilder().setName("js_context_list").setType(Type.BYTES).setDataBytes(Reference.newBuilder().setKey(i).setStore(1));
				ObjectData objectData = ObjectData.newBuilder().setId(1).addAttrs(attr).build();
				JsAnalyzerTask analyzerTask = new JsAnalyzerTask(new TaskContext(2, 3, 4, null), new ParametersWrapper(), new ObjectDataWrapper(objectData) , new JsCommandLineParams());
				//System.out.println("md5 b " + (System.nanoTime() - start));
				analyzerTask.process();
				//System.out.println("md5 a " + (System.nanoTime() - start));
			}
		}
		System.out.println("md5 " + (System.nanoTime() - start));
	}
	
	
	
	@Test
	public void allTests() throws Exception{
		for(int i = 0;i<10 ;i++){
			processTest();
			processTest1();
			System.out.println();
		}
	}
}
