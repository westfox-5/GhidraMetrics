package ghidrametrics.base;

import java.math.BigDecimal;

public class NumericMetric extends BaseMetric<BigDecimal> {

	public NumericMetric(BaseMetricKey mKey, Double value) {
		this(mKey, BigDecimal.valueOf(value));
	}

	public NumericMetric(BaseMetricKey mKey, BigDecimal value) {
		super(mKey, value);
	}
}
