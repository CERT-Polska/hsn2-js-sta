package pl.nask.hsn2.service.analysis;

/**
 * Non thread safe.
 */
public class MyCircularCharBuffer2 {
	/**
	 * True means that buffer changed since last string generation time, so we have to generate new one.
	 */
	private boolean isChanged = true;
	private String asString;
	private StringBuilder buffer;

	public MyCircularCharBuffer2(int size) {
		buffer = new StringBuilder(size);
		for (int i = 0; i < size; i++) {
			buffer.append(' ');
		}
	}

	// Adding elements:
	// [...] head=0, getAsString=...
	// [a..] head=1, getAsString=..a
	// [ab.] head=2, getAsString=.ab
	// [abc] head=0, getAsString=abc
	// [dbc] head=1, getAsString=bcd
	// [dec] head=2, getAsString=cde
	// [def] head=0, getAsString=def

	public void add(char ch) {
		buffer.deleteCharAt(0);
		buffer.append(ch);
	}

	public String getAsString() {
		if (isChanged) {
			asString = buffer.toString();
		}
		return asString;
	}
}
