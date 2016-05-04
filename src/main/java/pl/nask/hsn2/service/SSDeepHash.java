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

package pl.nask.hsn2.service;

import java.security.InvalidParameterException;
import java.util.StringTokenizer;

public class SSDeepHash implements Comparable<SSDeepHash>{
	private final int match;
	private final String hash;

	public SSDeepHash(int match, String hash) {
		this.match = match;
		this.hash = hash;
	}

	public SSDeepHash(String readLine) {
		String line = readLine.trim();
		StringTokenizer tokenizer = new StringTokenizer(line);

		int count = tokenizer.countTokens();
		if(count == 2){
			match = Integer.valueOf(tokenizer.nextToken());
			hash = tokenizer.nextToken();
		}
		else{
			throw new InvalidParameterException("Expect 2 tokens, but found " + count + " in line " + line);
		}
	}

	public final int getMatch() {
		return match;
	}

	public final String getHash() {
		return hash;
	}

	@Override
	public final int compareTo(SSDeepHash o) {
		return match - o.match;
	}

	@Override
	public final boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof SSDeepHash)) {
			return false;
		}
		SSDeepHash s = (SSDeepHash) o;
		return match == s.match && hash.equals(s.hash);
	}

	@Override
	public final int hashCode() {
		return hash.hashCode();
	}
}
