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

import java.io.File;

public final class NGramsCalc {
    private static volatile NGramsCalc ngrams = null;
    private native String calcNgrams(String inFilename, String buffer, int length, int limit);

    public static void initialize(String libPath){
        if (ngrams == null) {
        	System.load(new File(libPath).getAbsolutePath());
            ngrams = new NGramsCalc();
        }
    }

    /**
     * Utility class, should not be instantiated.
     */
    private NGramsCalc() {
    }

    public static String getNgramsForFile(String inFilename, int length, int limit) {

        return ngrams.calcNgrams(inFilename, "", length, limit);
    }

    public static String getNgramsForString(String buffer, int length, int limit) {
        if (ngrams == null) {
            throw new IllegalStateException("Not initialized");
        }
        return ngrams.calcNgrams("", buffer, length, limit);
    }
}
