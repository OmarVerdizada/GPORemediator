# 3.14.2 — English interface and consistent themes

The interface, settings, connection guidance, generated user-facing messages and maintained documentation are now English. Previous language preferences migrate to English. Application identity and authorization behavior are unchanged.

Light and dark themes use the same semantic colors for settings, fields, buttons, status notes and modal surfaces. The settings rail now matches its two actual steps. Mobile panels fit the viewport, and input text, placeholders and focus rings follow the selected theme.

Browser regressions cover legacy language preference migration, light/dark/system switching, text contrast and mobile overflow. The release archive is rebuilt from the updated source.

## Upgrade

Pull main or extract the complete updated package, stop the old instance and restart GpoRemediator.cmd. The launcher refreshes the packaged runtime. Reload the browser to receive the versioned assets. Configuration, delegation and audit history remain in ProgramData.
