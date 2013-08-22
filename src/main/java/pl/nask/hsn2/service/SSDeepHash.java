package pl.nask.hsn2.service;

import java.security.InvalidParameterException;
import java.util.StringTokenizer;

public class SSDeepHash {
	private final int match;
	private final String hash;
	
	public SSDeepHash(int match, String hash) {
		this.match = match;
		this.hash = hash;
	}
	
	public SSDeepHash(String readLine) {
		readLine = readLine.trim();
		StringTokenizer tokenizer = new StringTokenizer(readLine);
		
		int count = tokenizer.countTokens();
		if(count == 2){
			match = new Integer(tokenizer.nextToken());
			hash = tokenizer.nextToken();
		}
		else{
			throw new InvalidParameterException("Expect 2 tokens, but found " + count + " in line " + readLine);
		}
	}

	public int getMatch() {
		return match;
	}

	public String getHash() {
		return hash;
	}
}
