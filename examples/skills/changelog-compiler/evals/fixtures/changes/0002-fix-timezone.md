Type: Fixed
Summary: Correct off-by-one in the weekly rollup when the range crosses a month boundary.

The date-range header previously dropped the final day of a month; it now counts the
boundary day in the correct week.
