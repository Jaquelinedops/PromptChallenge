-- Prompt Challenge - migration 05: restore appeals and persistent victories.
-- Apply AFTER the existing 04_replay_history_timers.sql migration.
-- Back up the production database first. Safe to run again.
BEGIN;

ALTER TABLE progress ADD COLUMN IF NOT EXISTS ever_passed boolean NOT NULL DEFAULT false;
UPDATE progress p SET ever_passed=true
WHERE p.status='passed' AND p.ever_passed=false;
-- Backfill historical successful evaluations without modifying their original verdict.
UPDATE progress p SET ever_passed=true
WHERE p.ever_passed=false AND EXISTS (
 SELECT 1 FROM attempts a WHERE a.user_id=p.user_id AND a.challenge_id=p.challenge_id AND a.result=true
);

CREATE TABLE IF NOT EXISTS judgment_appeals (
 id BIGSERIAL PRIMARY KEY,
 user_id UUID NOT NULL REFERENCES users(id),
 challenge_id UUID NOT NULL REFERENCES challenges(id),
 run_no INTEGER NOT NULL,
 attempt_id TEXT NOT NULL UNIQUE,
 reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 15 AND 2000),
 status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
 admin_note TEXT NOT NULL DEFAULT '',
 reviewed_by UUID REFERENCES users(id),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 decided_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS judgment_appeals_status_created_idx ON judgment_appeals(status,created_at);
CREATE INDEX IF NOT EXISTS judgment_appeals_user_challenge_idx ON judgment_appeals(user_id,challenge_id,run_no);

-- A single transaction must decide an appeal and award the win.
-- Only an approved administrator can call this function successfully.
CREATE OR REPLACE FUNCTION pc_resolve_appeal(p_appeal_id bigint,p_admin_id uuid,p_decision text,p_note text)
RETURNS text LANGUAGE plpgsql AS $$
DECLARE ap judgment_appeals%ROWTYPE; v_attempt RECORD;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM users WHERE id=p_admin_id AND role='admin' AND status='approved') THEN
  RETURN 'forbidden';
 END IF;
 IF p_decision NOT IN ('approved','rejected') THEN RETURN 'invalid'; END IF;
 SELECT * INTO ap FROM judgment_appeals WHERE id=p_appeal_id FOR UPDATE;
 IF NOT FOUND THEN RETURN 'not_found'; END IF;
 IF ap.status<>'pending' THEN RETURN 'already_resolved'; END IF;
 SELECT id, result, user_id, challenge_id, run_no INTO v_attempt FROM attempts
 WHERE id::text=ap.attempt_id AND user_id=ap.user_id AND challenge_id=ap.challenge_id AND run_no=ap.run_no;
 IF NOT FOUND OR v_attempt.result IS DISTINCT FROM false THEN RETURN 'invalid_attempt'; END IF;
 UPDATE judgment_appeals SET status=p_decision,admin_note=left(coalesce(p_note,''),2000),reviewed_by=p_admin_id,decided_at=now() WHERE id=ap.id;
 IF p_decision='approved' THEN
  UPDATE progress SET ever_passed=true,
    status=CASE WHEN run_no=ap.run_no THEN 'passed' ELSE status END,
    completed_at=CASE WHEN run_no=ap.run_no THEN now() ELSE completed_at END,
    generation=CASE WHEN run_no=ap.run_no THEN generation+1 ELSE generation END,
    operation_token=CASE WHEN run_no=ap.run_no THEN NULL ELSE operation_token END,
    operation_expires_at=CASE WHEN run_no=ap.run_no THEN NULL ELSE operation_expires_at END
  WHERE user_id=ap.user_id AND challenge_id=ap.challenge_id;
  UPDATE challenge_runs SET won=true,completed_at=coalesce(completed_at,now())
  WHERE user_id=ap.user_id AND challenge_id=ap.challenge_id AND run_no=ap.run_no;
 END IF;
 RETURN 'resolved';
END; $$;
COMMIT;
