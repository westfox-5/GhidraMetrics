package it.unive.ghidra.metrics.base.interfaces;

public interface GMMetricKey {
	public static final String KEY_INFO_DESCRIPTION = "description";
	public static final String KEY_INFO_FORMULA = "formula";

	public static enum Type {
		STRING, NUMERIC
	};

	String getName();

	Type getType();

	int getSortingNumber();
	
	String getInfo(String infoKey);
}
