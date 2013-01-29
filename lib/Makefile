CXXFLAGS=-fPIC
CFLAGS = -fPIC -I/usr/lib/jvm/java-6-sun/include -I/usr/lib/jvm/java-6-sun/include/linux
HDRS = mystring.h INgrams.h ngrams.h CharNgrams.h WordNgrams.h text2wfreq.h pl_nask_hsn_ngrams_NGramsCalc.h
SRCS = string.cpp INgrams.cpp ngrams.cpp CharNgrams.cpp WordNgrams.cpp text2wfreq.cpp pl_nask_hsn_ngrams_NGramsCalc.cpp
OBJS = string.o INgrams.o ngrams.o CharNgrams.o WordNgrams.o text2wfreq.o pl_nask_hsn_ngrams_NGramsCalc.o
# OBJS = $(SRCS:.c.cpp=.o)
TARGET = libngrams.so

default : $(TARGET)

#ngrams.dll : $(OBJS)
#	g++ -Wall -D_JNI_IMPLEMENTATION_ -Wl,--kill-at -shared $(CFLAGS) -o $(TARGET) $(OBJS)
libngrams.so : $(OBJS)
	g++ -fPIC -shared -I/usr/lib/jvm/java-6-sun/include -o $(TARGET) $(OBJS)

string.o: mystring.h
INgrams.o: INgrams.h
ngrams.o: ngrams.h
CharNgrams.o: CharNgrams.h
WordNgrams.o: WordNgrams.h
text2wfreq.o: text2wfreq.h

pl_nask_hsn_ngrams_NGramsCalc.o: pl_nask_hsn_ngrams_NGramsCalc.cpp pl_nask_hsn_ngrams_NGramsCalc.h
	g++ $(CFLAGS) -c -o pl_nask_hsn_ngrams_NGramsCalc.o pl_nask_hsn_ngrams_NGramsCalc.cpp

rebuild:
	make clean
	make

clean : 
	@echo "Removing all object files..."
	rm core *.o $(TARGET)
