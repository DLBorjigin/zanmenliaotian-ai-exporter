# Contact-only export

Treat user requests for 微信好友 and 微信联系人 as synonyms for the default
filtered list, not separate populations. The default files 微信联系人.xlsx and
微信联系人.csv are two formats of the same list; explain that users need only
open the XLSX. Do not rename CSV bytes to .xls or .xlsx. All cached accounts,
including non-friends, still require an explicit all-records request.

For a request to export contacts, use `export-contacts-auto-key` instead of chat
export. Discover the active account first, and obtain consent for the exact
contact.db read-only process scan (20 seconds) and exporting private contact
metadata. A general chat export permission does not authorize a contact list.

```
scripts/wechat_export.py export-contacts-auto-key --contact-database <exact contact.db> --output-dir <private output> --confirm-read-process-memory --confirm-export-contacts
```

Default `--scope friends` exports only conservative local friend markers:
`local_type=1 AND (flag & 3)=3 AND delete_flag=0 AND verify_flag=0`, excluding
group, public-account and known system identifiers. Missing relationship columns
fail closed; NULL, negative or conflicting flags never qualify. Do not infer
friendship from remarks, aliases, conversation history or common groups.
This local-cache rule is not proof of mutual friendship or complete server state.
Ask the user to compare with their address book before claiming completeness.
Use `--scope all` only when the user explicitly requests all cached contacts,
including non-friends; never silently fall back to it.

The ZIP contains Excel worksheets and UTF-8 BOM CSVs separated by category.
It exports nickname, remark, locally stored alias, a hashed record identifier,
category and local relationship status. No phone, avatar, extended metadata,
group member list or message body is selected. Plaintext and encrypted temporary
snapshots are removed by the command. Never put exports in release material.

Do not describe ordinary contact rows as confirmed friends. The database may
contain non-friends, old records or the account owner. Group and public-account
prefixes are category hints, not evidence of current membership or subscription.
The system account list is deliberately incomplete; unknown records remain
other contacts with unverified friendship, excluded by default. Exact duplicate records collapse;
conflicting records are retained. An alias can be absent or stale. Hashes are
pseudonymous identifiers, not a guarantee of anonymity.

Return only aggregate counts in chat, plus the local ZIP link when requested.
This command currently uses supported Windows automatic-key adapters only.
