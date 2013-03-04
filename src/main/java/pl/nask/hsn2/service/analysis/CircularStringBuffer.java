package pl.nask.hsn2.service.analysis;

/**
 * Non thread safe.
 */
public class CircularStringBuffer {
	private StringBuilder buffer;

	public CircularStringBuffer(int size) {
		int sizeSafe = size;
		if (size < 1) {
			sizeSafe = 1;
		}
		buffer = new StringBuilder(sizeSafe);
		for (int i = 0; i < sizeSafe; i++) {
			buffer.append(' ');
		}
	}

	public void add(char ch) {
		buffer.deleteCharAt(0);
		buffer.append(ch);
	}

	public String getAsString() {
		return buffer.toString();
	}
}
