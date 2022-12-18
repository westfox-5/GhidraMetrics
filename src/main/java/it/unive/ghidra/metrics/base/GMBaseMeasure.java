package it.unive.ghidra.metrics.base;

import java.util.Objects;

import it.unive.ghidra.metrics.base.interfaces.GMMeasure;
import it.unive.ghidra.metrics.base.interfaces.GMMeasureKey;

public class GMBaseMeasure<T> implements GMMeasure<T> {
	private final GMMeasureKey key;
	private final T value;

	protected GMBaseMeasure(GMMeasureKey key, T value) {
		this.key = key;
		this.value = value;
	}
	
	@Override
	public GMMeasureKey getKey() {
		return key;
	}

	@Override
	public T getValue() {
		return value;
	}

	@Override
	public int hashCode() {
		return Objects.hash(key);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GMBaseMeasure<?> other = (GMBaseMeasure<?>) obj;
		return Objects.equals(key, other.key);
	}

}
