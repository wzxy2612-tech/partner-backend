-- Outbox state-machine inconsistencies. READ ONLY -- this file changes nothing.
--
-- 0017 refuses to run while any of these exist, because the correct value for
-- each is a judgment about what actually happened and a migration that picks
-- one invents history. Same line 0012 drew for cross-company parent chains.
--
-- RUN THIS AS A SUPERUSER (psql -U postgres), not as app_owner.
--
-- outbox_events is FORCE ROW LEVEL SECURITY, and the policy is
--     partner_id = <app.partner_id> AND partner_is_active(<app.partner_id>)
-- so the owner sees nothing without a tenant scope, and even WITH one it sees
-- nothing for a suspended partner. The table's own protection hides these rows
-- from the audit that is supposed to find them. That is the correct default and
-- it is why this script names the role it needs instead of failing quietly with
-- zero rows -- an empty result here means "you are not allowed to look", not
-- "there is nothing wrong".
--
-- Ids are safe to copy into a ticket. token_ciphertext and token_nonce are not,
-- and are deliberately not selected below.

\echo '== pending with no payload: cannot ever be delivered =='
SELECT id, partner_id, invitation_id, created_at, attempts, last_error
FROM outbox_events
WHERE status = 'pending'
  AND (token_ciphertext IS NULL OR token_nonce IS NULL)
ORDER BY created_at;

\echo '== pending already marked delivered: sent_at set on a pending row =='
SELECT id, partner_id, invitation_id, sent_at, attempts
FROM outbox_events
WHERE status = 'pending' AND sent_at IS NOT NULL
ORDER BY sent_at;

\echo '== failed carrying a delivery timestamp =='
SELECT id, partner_id, invitation_id, sent_at, last_error
FROM outbox_events
WHERE status = 'failed' AND sent_at IS NOT NULL
ORDER BY sent_at;

\echo '== sent with no delivery timestamp =='
SELECT id, partner_id, invitation_id, attempts, last_error
FROM outbox_events
WHERE status = 'sent' AND sent_at IS NULL
ORDER BY id;

\echo '== terminal rows still holding a recoverable payload =='
\echo '   (0017 clears these automatically -- listed for the record, not for action)'
SELECT id, partner_id, status, sent_at,
       token_ciphertext IS NOT NULL AS has_ciphertext,
       token_nonce      IS NOT NULL AS has_nonce
FROM outbox_events
WHERE status IN ('sent', 'failed')
  AND (token_ciphertext IS NOT NULL OR token_nonce IS NOT NULL)
ORDER BY status, id;
