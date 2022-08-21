package ghidrametrics.util;

import java.math.BigDecimal;
import java.math.RoundingMode;

public class StringUtils {
	public static boolean isEmpty(String str) {
		if (str == null) return true;
		if (str.trim().isEmpty()) return true;
		return false;
	}
	
	public static boolean notEmpty(String str) {
		return !isEmpty(str);
	}
	
	public static String quotate(Object s) {
		if (s instanceof BigDecimal) {
			BigDecimal bd = (BigDecimal)s;
			return bd.setScale(3, RoundingMode.HALF_UP).toPlainString();
		}
		return "\""+s+"\"";
	}
}
