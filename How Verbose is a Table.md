```sql
AzureDiagnostics        // <--Define the table to query
| summarize count() by bin(TimeGenerated,1d)    // <--Return count per day
| render columnchart        // <--Graph a column chart
```
