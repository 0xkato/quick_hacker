# Sink-Directed Shift Steering

## Purpose
Shift a lane from broad exploration to directed fuzzing toward a specific dangerous sink when static analysis identifies high-value targets.

## Trigger
- Static analysis identifies reachable dangerous sink (exec, eval, SQL query builder)
- Current coverage shows path toward sink but not reaching it
- Manual analyst request for targeted investigation

## Actions
- Switch methodology to directed pack
- Configure distance metric toward target sink
- Narrow input mutation to parameters on the path to sink

## Notes
Highest-priority steering signal. Directed lanes have shorter budgets but higher expected yield per minute.
