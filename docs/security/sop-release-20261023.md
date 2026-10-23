# [F007][S005] SOP release assessment

Owner-authorized changes: explicit coach scheduling before each lesson; same-day/new-student flexibility; consumed session lock; day/week/month calendar; Admin-only audited payment edits. No production test attendance/payment or WhatsApp sends. No database schema change. Existing records remain stored; inferred recurring dates are no longer independently actionable. Student row lock serializes attendance and repeated same-day check-in remains rejected. Confirmed financial amount edits return 409 to preserve installment PIN gates.

Next.js 16.4.0 scan found GHSA-2464-fhr4-w9xw, GHSA-p3m5-59mp-jv5r and GHSA-673q-mjm6-r5xr. Patched to 16.4.1 (official advisory https://github.com/advisories/GHSA-2464-fhr4-w9xw). Automatic audit fix tried an unavailable 16.4.3 tarball; explicitly pinned the available documented patch. Full/runtime audit rerun before release.

Backend tests include unconfirmed PIN rejection, consumed picker removal, next-lesson rebooking, permission/conflict guards, payment persistence/audit and confirmed-fund protection. Browser tests cover all calendar views, overlap positions, locked lessons and payment save/reload, plus prior signature/booking regressions. Production screen verification uses the existing Fung account without modifying customer records.

Validation: backend suite 95 passed; focused browser suite 6 passed on patched Next.js 16.4.1; 58-route webpack production build passed; pip-audit and full/runtime npm audits report zero known vulnerabilities. Build required network access for the existing Google Fonts download.

Final financial-state review: lock and refresh linked course rows before correction, serializing against concurrent payment confirmation; reject amount changes when an earlier tranche is already confirmed even if the UI projection is pending for the next tranche. Added regression; backend suite 96 passed.
