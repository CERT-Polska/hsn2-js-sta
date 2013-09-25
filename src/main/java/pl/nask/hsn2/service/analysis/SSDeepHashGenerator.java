package pl.nask.hsn2.service.analysis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;

public class SSDeepHashGenerator {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SSDeepHashGenerator.class);
	private static NativeLibrary nativeLibrary;
	private final static int HASH_BYTE_ARRAY_LENGTH = 180;
	
	public static void initialize(String libName) {
		LOGGER.info("Loading ssdeep library");
		nativeLibrary = NativeLibrary.getInstance(libName);
		LOGGER.info("ssdeep library loaded");
		
	}
	
	public String generateHash(String doc){
		synchronized (nativeLibrary){
			Function function = nativeLibrary.getFunction("fuzzy_hash_buf");
			byte[] result = new byte[HASH_BYTE_ARRAY_LENGTH];
			int i = function.invokeInt(new Object[] {doc, doc.length(), result});
			if(i == 0){
				String hash = new String(result).trim();
				LOGGER.debug(hash);
				return hash;
			}
			else{
				throw new IllegalStateException("Can not generate hash for: " + doc);
			}
		}
	}
	
	public String generateHashForFile(String path){
		synchronized (nativeLibrary){
			Function function = nativeLibrary.getFunction("fuzzy_hash_filename");
			byte[] result = new byte[HASH_BYTE_ARRAY_LENGTH];
			int i = function.invokeInt(new Object[] {path, result});
			if(i == 0){
				String hash = new String(result).trim();
				LOGGER.debug(hash);
				return hash;
			}
			else{
				throw new IllegalStateException("Can not generate hash for: " + path);
			}
		}
	}
	
	public int compare(String fromList, String generated){
		if(!fromList.equals(generated)){
			synchronized (nativeLibrary){
				Function function = nativeLibrary.getFunction("fuzzy_compare");
				int result = function.invokeInt(new Object[] {fromList, generated});
				LOGGER.debug("from whiteList: " + fromList + " generated: " + generated + " result: " + result);
				if(result != -1){
					return result;
				}
				else{
					throw new IllegalStateException("Can not compare hashes: " + fromList + " " + generated);
				}
			}
		}
		else{
			return 100;
		}
	}
}
