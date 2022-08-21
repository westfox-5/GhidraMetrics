package ghidrametrics.util;

import java.math.BigDecimal;
import java.math.MathContext;

public class NumberUtils {

	public static final MathContext DEFAULT_CONTEXT = MathContext.DECIMAL64;

	public static boolean notEqual(BigDecimal a, BigDecimal b) {
		return !isEqual(a, b);
	}

	/**
	 * @see Pitfall #4 in: <a href=
	 *      "https://blogs.oracle.com/javamagazine/post/four-common-pitfalls-of-the-bigdecimal-class-and-how-to-avoid-them">https:blogs.oracle.com</a>
	 */
	public static boolean isEqual(BigDecimal a, BigDecimal b) {
		return a.compareTo(b) == 0;
	}

	public static BigDecimal log2(BigDecimal n) {
		return log2(n.doubleValue());
	}

	public static BigDecimal log2(Integer n) {
		return log2(n.doubleValue());
	}

	public static BigDecimal log2(Double n) {
		return new BigDecimal(Math.log(n) / Math.log(2));
	}
}
