#include "pl_nask_hsn_ngrams_NGramsCalc.h"
#include "text2wfreq.h"

JNIEXPORT jstring JNICALL Java_pl_nask_hsn2_service_analysis_NGramsCalc_calcNgrams
  (JNIEnv *env, jobject obj, jstring input, jstring buffer, jint length, jint limit) {

	const char *in = env->GetStringUTFChars(input, NULL);
	const char *buf = env->GetStringUTFChars(buffer, NULL);
	
	int n = length;
	int l = limit;

	INgrams * ngrams = NULL;

	ngrams = new CharNgrams(n, in, buf);
	
	jstring j = env->NewStringUTF(ngrams->output(limit).c_str());
	
	delete ngrams;
	delete in;
	delete buf;

	return j;

}
