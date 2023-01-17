package it.unive.ghidra.metrics.base.interfaces;

import java.util.Collection;

public interface GMMeasureKey {
	public static final String KEY_INFO_DESCRIPTION = "description";
	public static final String KEY_INFO_FORMULA = "formula";

	public static enum Type {
		STRING, NUMERIC
	};

	String getName();

	Type getType();

	int getSortingNumber();
	
	String addInfo(String infoKey, String info);

	String getInfo(String infoKey);
	
	Collection<String> getInfoKeys();
}
