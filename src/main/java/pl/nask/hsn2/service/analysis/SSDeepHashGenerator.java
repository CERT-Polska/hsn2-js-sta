/*
 * Copyright (c) NASK, NCSC
 * 
 * This file is part of HoneySpider Network 2.1.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;

public class SSDeepHashGenerator {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(SSDeepHashGenerator.class);
	private static final int HASH_BYTE_ARRAY_LENGTH = 180;
	private static final int SSDEEP_EQUALS_VAL = 100;
	private static NativeLibrary nativeLibrary;
	
	public static void initialize(String libName) {
		LOGGER.info("Loading ssdeep library");
		nativeLibrary = NativeLibrary.getInstance(libName);
		LOGGER.info("ssdeep library loaded");
		
	}
	
	public final String generateHash(String doc){
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
	
	public final String generateHashForFile(String path){
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
	
	public final int compare(String fromList, String generated){
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
			return SSDEEP_EQUALS_VAL;
		}
	}
}
