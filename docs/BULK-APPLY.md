# Bulk Apply

1. Open **Benchmark → Bulk apply**. Select controls with their checkboxes, or expand a section and choose **Use this group**. A batch contains at most 20 controls; group selection replaces the current basket.
2. Choose the shared GPO and target OU/domain. Expand controls to adjust their values. If user controls need session checks, record the computer OU where those users sign in and, optionally, the verification user. Complete the environment review for controls requiring it.
3. Select optional post-apply refresh, then **Generate bulk preview**. This step performs no policy writes. Inspect every requested value, existing link, AD value, warning and execution order.
4. Enter the change reference, acknowledge impact and any protected GPO, type **APPLY**, and submit. Closing the panel does not cancel accepted server work. Reloading does not repeat it. Open **Operations → Bulk operations** to resume the receipt.
5. Inspect results per control. **All selected GPO settings saved** confirms GPO publication and links; endpoint counters provide separate effective-value evidence. Unavailable endpoints are not successful measurements. A failure stops subsequent writes; already completed changes remain recorded.

For recovery, open the bulk receipt and choose **Rollback batch**. Type **ROLLBACK** and optionally request refresh of the recorded contexts. This restores the first changed control's complete GPO snapshot and all changed AD properties captured in that batch. It can affect every existing link of that GPO. Drift and delegated authority are checked before restoration. A successful snapshot restore and a failed endpoint refresh remain separate results.

Choose another group and repeat Preview/approval for a section larger than 20 controls. Each batch uses one GPO and scope. Multiple AD domains require their own connection, target and reviewed batch. User and Computer policies may coexist in a GPO; effective application still depends on the objects and sessions in scope. Security filtering, inheritance, WMI filters and winning-GPO attribution are not silently changed.
