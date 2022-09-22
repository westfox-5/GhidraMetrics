package it.unive.ghidra.metrics.base;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public abstract class GMBaseMetricKey implements GMiMetricKey, Comparable<GMBaseMetricKey> {

	private final String name;
	private final GMiMetricKey.Type type;
	private final int sortingNumber;

	private final Map<String, String> data = new HashMap<>();

	public GMBaseMetricKey(GMiMetricKey.Type type, String name, int sn) {
		this.type = type;
		this.name = name;
		this.sortingNumber = sn;
	}

	public GMBaseMetricKey(GMiMetricKey.Type type, String name, String description, String formula, int sn) {
		this(type, name, sn);
		if (description != null)
			data.put(KEY_DESCRIPTION, description);
		if (formula != null)
			data.put(KEY_FORMULA, formula);
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
	public void addInfo(String key, String value) {
		data.put(key, value);
	}

	@Override
	public String getInfo(String key) {
		return data.get(key);
	}

	@Override
	public Collection<String> getAllInfo() {
		return data.keySet();
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
