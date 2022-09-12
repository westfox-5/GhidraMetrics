package it.unive.ghidra.metrics.util;

import java.io.File;
import java.math.BigDecimal;
import java.math.RoundingMode;

import org.apache.commons.io.FilenameUtils;

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

	public static String getFileExtension(File arg0) {
		if (arg0 == null) return null;
		return FilenameUtils.getExtension(arg0.getAbsolutePath());
	}
	
	public static String getterMethodName(String name) {
		return "get" + name.substring(0, 1).toUpperCase() + name.substring(1).replace(" ", "");
	}

}
