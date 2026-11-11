# Bulk Apply

1. Open **Benchmark → Bulk apply**. Select controls with their checkboxes, or expand a section and choose **Use this group**. A batch contains at most 20 controls; group selection replaces the current basket.
2. Choose the shared GPO and target OU/domain. Expand controls to adjust their values. If user controls need session checks, record the computer OU where those users sign in and, optionally, the verification user. Complete the environment review for controls requiring it.
3. Select optional post-apply refresh, then **Generate bulk preview**. Inspect requested values, existing links, AD values and execution order. **Policy conflicts & dependencies** shows linked GPOs, affected scopes and related controls. A shared field with incompatible values blocks Apply.
4. Enter the change reference, acknowledge impact and any protected GPO, type **APPLY**, and submit. Closing the panel does not cancel accepted server work. Reloading does not repeat it. Open **Operations → Bulk operations** to resume the receipt.
5. Inspect the **GPO result** and **Endpoint evidence** for each control. Expand **Host evidence** for observations, unavailable probes and mismatches. A write failure stops subsequent writes and retains the receipts of completed changes.

For a single control, open **Operations → Bulk operations → View bulk result**, then **Review rollback** on the newest changed control. Run **Check rollback availability**, type **ROLLBACK** and choose optional endpoint refresh. Restore controls in reverse publication order to preserve earlier changes.

Choose **Rollback batch** to restore the earliest remaining GPO snapshot and the associated AD account-policy values. Restoration can affect every link of that GPO. The app checks live drift and delegated authority before restoration and records endpoint refresh separately.

Choose another group and repeat Preview/approval for a section larger than 20 controls. Each batch uses one GPO and scope. Multiple AD domains require their own connection, target and reviewed batch. User and Computer policies may coexist in a GPO; effective application still depends on the objects and sessions in scope. Security filtering, inheritance, WMI filters and winning-GPO attribution are not silently changed.
