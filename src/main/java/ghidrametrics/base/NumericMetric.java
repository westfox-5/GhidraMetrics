package ghidrametrics.base;

import java.math.BigDecimal;

public class NumericMetric extends BaseMetricValue<BigDecimal> {

	public NumericMetric(BaseMetricKey mKey, Double value) {
		this(mKey, BigDecimal.valueOf(value));
	}

	public NumericMetric(BaseMetricKey mKey, BigDecimal value) {
		super(mKey, value);
	}
}
