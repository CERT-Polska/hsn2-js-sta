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

import org.testng.annotations.Test;

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
import pl.nask.hsn2.service.analysis.SSDeepHashGenerator;
import pl.nask.hsn2.utils.DataStoreHelper;
import pl.nask.hsn2.wrappers.ObjectDataWrapper;
import pl.nask.hsn2.wrappers.ParametersWrapper;

import com.rabbitmq.client.AMQP.Queue.DeclareOk;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.QueueingConsumer;

public class FullProcessHashTest {

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
	
	@Test
	@SuppressWarnings({"static-access", "rawtypes", "unused"})
	public void processTest() throws Exception {

		new NonStrictExpectations() {
			@Mocked
			DataStoreConnectorImpl ds;
			
			@Mocked
			DataStoreHelper dsh;
			
			@Mocked(stubOutClassInitialization = true)
			JsCommandLineParams jsCMD;
			
			@Mocked(stubOutClassInitialization = true)
			NGramsCalc nGramsCalc;
			
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
				jsCMD.getTrainingSetPath();
				result = "weka.arff";
				
				jsCMD.getWhitelistPath();
				result = "src/test/resources/whitelist.ssdeep";
				
				jsCMD.getClassifierName();
				result = "weka.classifiers.bayes.NaiveBayes";
				
				jsCMD.getNgramLength();
				result = 4;
				
				jsCMD.getNgramQuantity();
				result = 50;
				
				nGramsCalc.getNgramsForFile(anyString, anyInt, anyInt);
				result = "_USE USER SER_ ER_I R_ID _ID_ __ __ _W W Q Q_ Q_O Q_O _O O I I_ I_G I_G _G G A A_ A_F A_FU _FUN FUNC UNCT NCTI CTIO TION ION_ ON_S N_SU _SUB SUBM UBMI BMIT MIT_ IT_B T_BU _BUT BUTT UTTO TTON TON_ ON_U N_US ID_V ";
			}
		};
		SSDeepHashGenerator.initialize("libfuzzy.so.2"); 
		JSWekaAnalyzer analyzer = new JSWekaAnalyzer(0, 0,"weka.arff", "weka.classifiers.bayes.NaiveBayes");
		for(int j = 0; j < 10; j++){
			for(int i = 1; i < 5; i++) {
				Attribute.Builder attr = Attribute.newBuilder().setName("js_context_list").setType(Type.BYTES).setDataBytes(Reference.newBuilder().setKey(i).setStore(1));
				ObjectData objectData = ObjectData.newBuilder().setId(1).addAttrs(attr).build();
				analyzer.prepare(new String[] { "" }, new String[] { "" }, null);
				
				JsAnalyzerTask analyzerTask = new JsAnalyzerTask(new TaskContext(2, 3, 4, null), new ParametersWrapper(), new ObjectDataWrapper(objectData) , new JsCommandLineParams(), analyzer);
				analyzerTask.process();
				analyzer.eraseLists();
			}
		}
	}
}
