package pl.nask.hsn2.service.analysis;

/**
 * Non thread safe.
 */
public class CircularStringBuffer {
	/**
	 * True means that buffer changed since last string generation time, so we have to generate new one.
	 */
	private boolean isChanged = true;
	private String asString;
	private StringBuilder buffer;

	public CircularStringBuffer(int size) {
		buffer = new StringBuilder(size);
		for (int i = 0; i < size; i++) {
			buffer.append(' ');
		}
	}

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
