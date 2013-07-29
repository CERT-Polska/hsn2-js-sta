package pl.nask.hsn2.service.analysis;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.commons.io.IOUtils;

import pl.nask.hsn2.protobuff.Resources.JSContext;
import pl.nask.hsn2.protobuff.Resources.JSContextList;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;

public class SSDeepHashGenerator {
	
	private static NativeLibrary nativeLibrary = NativeLibrary.getInstance("/usr/lib/libfuzzy.so.2");
	
	
	public String generateHash(String doc){
		synchronized (nativeLibrary){
			Function function = nativeLibrary.getFunction("fuzzy_hash_buf");
			byte[] result = new byte[180];
			int i = function.invokeInt(new Object[] {doc, doc.length(), result});
			if(i == 0){
				return new String(result);
			}
			else{
				throw new IllegalStateException("Can not generate hash for: " + doc);
			}
		}
	}
	
	public String generateHashForFile(String path){
		long start = System.nanoTime();
		synchronized (nativeLibrary){
			Function function = nativeLibrary.getFunction("fuzzy_hash_filename");
			byte[] result = new byte[180];
			int i = function.invokeInt(new Object[] {path, result});
			//System.out.println("gene: " + (System.nanoTime() - start) + " " + result);
			if(i == 0){
				return new String(result);
			}
			else{
				throw new IllegalStateException("Can not generate hash for: " + path);
			}
		}
	}
	
	public int compare(String fromList, String generated){
		long start = System.nanoTime();
		synchronized (nativeLibrary){
			Function function = nativeLibrary.getFunction("fuzzy_compare");
			int result = function.invokeInt(new Object[] {fromList, generated});
			//System.out.println("comp: " + (System.nanoTime() - start) + " " + generated);
			if(result != -1){
				return result;
			}
			else{
				throw new IllegalStateException("Can not compare hashes: " + fromList + " " + generated);
			}
		}
	}
	
	public static void main(String[] args) throws IOException {
//		File f = new File("/home/rajdo/hsn/HSN2-git/hsn2-js-sta/README");
//		SSDeepHashGenerator generator = new SSDeepHashGenerator();
//		String s = generator.generateHashForFile("/home/rajdo/hsn/HSN2-git/hsn2-js-sta/README");
//		String s1 = generator.generateHashForFile("/home/rajdo/hsn/HSN2-git/hsn2-js-sta/spam4.log");
//		System.out.println(s);
//		System.out.println(s1);
//		System.out.println(generator.compare(s, s1));
		File f = new File("src/test/resources/2");
		InputStream in = new FileInputStream(f);
		String s = IOUtils.toString(in);
		JSContextList jsl = JSContextList.newBuilder().addContexts(JSContext.newBuilder().setSource(s).setEval(false).setId(1)).build();
		in.close();
		OutputStream out = new FileOutputStream(f);
		IOUtils.write(jsl.toByteArray(), out);
		out.flush();
		out.close();
		in.close();
		
	}
	
}
