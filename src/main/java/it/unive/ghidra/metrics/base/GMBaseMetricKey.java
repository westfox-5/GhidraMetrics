package it.unive.ghidra.metrics.base;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import it.unive.ghidra.metrics.base.interfaces.GMMetricKey;

public abstract class GMBaseMetricKey implements GMMetricKey, Comparable<GMBaseMetricKey> {
	protected static final Map<String, GMBaseMetricKey> lookupByName = new HashMap<>();
	
	private final String name;
	private final GMMetricKey.Type type;
	private final int sortingNumber;

	private final Map<String, String> data = new HashMap<>();

	public GMBaseMetricKey(GMMetricKey.Type type, String name, int sn) {
		this.type = type;
		this.name = name;
		this.sortingNumber = sn;
		
		lookupByName.put(this.getClass().getSimpleName() + "_" + this.getName(), this);
	}

	public GMBaseMetricKey(GMMetricKey.Type type, String name, String description, String formula, int sn) {
		this(type, name, sn);
		if (description != null)
			data.put(KEY_INFO_DESCRIPTION, description);
		if (formula != null)
			data.put(KEY_INFO_FORMULA, formula);
	}

	public static GMBaseMetricKey byName(Class<? extends GMBaseMetricKey> clz, String name) {
		return lookupByName.get(clz.getSimpleName() + "_" + name);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public Type getType() {
		return type;
	}

	@Override
	public int getSortingNumber() {
		return sortingNumber;
	}
	
	@Override
	public String getInfo(String infoKey) {
		return data.get(infoKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GMBaseMetricKey other = (GMBaseMetricKey) obj;
		return Objects.equals(name, other.name);
	}

	@Override
	public int compareTo(GMBaseMetricKey key) {
		if (key == null)
			return 1;
		return getSortingNumber() - key.getSortingNumber();
	}

}
