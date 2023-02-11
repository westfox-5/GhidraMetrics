package it.unive.ghidra.metrics.util;

import java.math.BigDecimal;
import java.math.MathContext;
import java.math.RoundingMode;

public class NumberUtils {

	private static final MathContext DEFAULT_CONTEXT = MathContext.DECIMAL64;

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

	public static BigDecimal nullToZero(BigDecimal a) {
		return a == null ? BigDecimal.ZERO : a;
	}

	public static BigDecimal nullToOne(BigDecimal a) {
		return a == null ? BigDecimal.ONE : a;
	}

	public static BigDecimal zeroToNull(BigDecimal a) {
		return isEqual(a, BigDecimal.ZERO) ? null : a;
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

	public static BigDecimal add(BigDecimal a, BigDecimal b) {
		return nullToZero(a).add(nullToZero(b), DEFAULT_CONTEXT);
	}

	public static BigDecimal sub(BigDecimal a, BigDecimal b) {
		return add(a, b.negate(DEFAULT_CONTEXT));
	}

	public static BigDecimal mul(BigDecimal a, BigDecimal b) {
		return nullToOne(a).multiply(nullToOne(b), DEFAULT_CONTEXT);
	}

	public static BigDecimal div(BigDecimal a, BigDecimal b) {
		return nullToOne(a).divide(zeroToNull(nullToOne(b)), DEFAULT_CONTEXT);
	}

	public static boolean gt0(BigDecimal a) {
		return nullToZero(a).compareTo(BigDecimal.ZERO) > 0;
	}

	public static boolean lte0(BigDecimal a) {
		return !gt0(a);
	}

	public static boolean gte0(BigDecimal a) {
		return nullToZero(a).compareTo(BigDecimal.ZERO) >= 0;
	}

	public static boolean lt0(BigDecimal a) {
		return !gte0(a);
	}
	
	public static BigDecimal scale(BigDecimal a, int scale) {
		return a.setScale(scale, RoundingMode.CEILING);
	}

}
