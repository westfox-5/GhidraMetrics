package it.unive.ghidra.metrics.base;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import it.unive.ghidra.metrics.base.interfaces.GMiMetricKey;

public class GMMetricKey implements GMiMetricKey {
	private final String name;
	private final GMiMetricKey.Type type;

	private final Map<String, String> data = new HashMap<>();

	public GMMetricKey(GMiMetricKey.Type type, String name) {
		this.type = type;
		this.name = name;
	}

	public GMMetricKey(GMiMetricKey.Type type, String name, String description, String formula) {
		this(type, name);
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
		GMMetricKey other = (GMMetricKey) obj;
		return Objects.equals(name, other.name);
	}
}
