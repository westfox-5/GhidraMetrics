package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMiMetricKey {

	public static final String KEY_DESCRIPTION = "description";
	public static final String KEY_FORMULA = "formula";

	public static enum Type {
		STRING, NUMERIC
	};

	String getName();

	Type getType();

	int getSortingNumber();

	void addInfo(String key, String value);

	String getInfo(String key);

	Collection<String> getAllInfo();
}
