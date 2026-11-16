-- Tichor consent-based messaging, v3. Production activation requires SQL Editor execution and post-deploy checks.
-- Uses existing verified table columns. Preserves message history.
-- IMPORTANT: Does not itself require verified email; Supabase Auth settings must enforce that.
BEGIN;
-- RLS does not govern TRUNCATE. Remove unnecessary broad privileges.
REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.chat_messages, public.tichor_call_events FROM authenticated;
REVOKE ALL ON public.tichor_contacts FROM anon;
REVOKE TRUNCATE, TRIGGER, REFERENCES ON public.tichor_contacts, public.tichor_profiles FROM authenticated;
CREATE TABLE IF NOT EXISTS public.tichor_contact_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 requester_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 recipient_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','declined','blocked')),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CONSTRAINT tichor_request_distinct CHECK(requester_id<>recipient_id),
 UNIQUE(requester_id,recipient_id)
);
CREATE INDEX IF NOT EXISTS tichor_contact_requests_recipient ON public.tichor_contact_requests(recipient_id,status);
ALTER TABLE public.tichor_contact_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.tichor_contact_requests FROM PUBLIC, anon;
REVOKE INSERT, UPDATE, DELETE ON public.tichor_contact_requests FROM authenticated;
GRANT SELECT ON public.tichor_contact_requests TO authenticated;
DROP POLICY IF EXISTS tichor_requests_read ON public.tichor_contact_requests;
CREATE POLICY tichor_requests_read ON public.tichor_contact_requests FOR SELECT TO authenticated USING (auth.uid()=requester_id OR auth.uid()=recipient_id);

CREATE OR REPLACE FUNCTION public.tichor_request_contact(target_username text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
DECLARE target uuid; prior text; normalized text;
BEGIN
 IF auth.uid() IS NULL OR auth.role()<>'authenticated' THEN RAISE EXCEPTION 'Sign in required'; END IF;
 normalized:=lower(trim(leading '@' from btrim(coalesce(target_username,''))));
 IF normalized !~ '^[a-z][a-z0-9_]{2,23}$' THEN RAISE EXCEPTION 'Enter a valid username'; END IF;
 SELECT p.user_id INTO target FROM public.tichor_profiles p WHERE lower(p.username)=normalized LIMIT 1;
 IF target IS NULL OR target=auth.uid() THEN RETURN 'If this username accepts requests, the request has been submitted.'; END IF;
 IF EXISTS(SELECT 1 FROM public.tichor_contact_requests r WHERE r.status='blocked' AND
 ((r.requester_id=target AND r.recipient_id=auth.uid()) OR (r.requester_id=auth.uid() AND r.recipient_id=target))) THEN
 RETURN 'If this username accepts requests, the request has been submitted.'; END IF;
 SELECT r.status INTO prior FROM public.tichor_contact_requests r WHERE r.requester_id=auth.uid() AND r.recipient_id=target;
 IF prior IS NULL THEN
 INSERT INTO public.tichor_contact_requests(requester_id,recipient_id) VALUES(auth.uid(),target);
 ELSIF prior='declined' THEN
 -- Declines are final until the recipient chooses to initiate a new request.
 NULL;
 END IF;
 RETURN 'If this username accepts requests, the request has been submitted.';
END $$;

CREATE OR REPLACE FUNCTION public.tichor_respond_contact(request_id uuid, decision text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF auth.uid() IS NULL OR auth.role()<>'authenticated' THEN RAISE EXCEPTION 'Sign in required'; END IF;
 IF decision NOT IN ('accepted','declined','blocked') THEN RAISE EXCEPTION 'Invalid response'; END IF;
 UPDATE public.tichor_contact_requests SET status=decision,updated_at=now()
 WHERE id=request_id AND recipient_id=auth.uid() AND status='pending';
 IF NOT FOUND THEN RAISE EXCEPTION 'Pending request not found'; END IF;
END $$;

-- A participant may block an existing relationship in either direction.
CREATE OR REPLACE FUNCTION public.tichor_block_contact(other_id uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path='' AS $$
BEGIN
 IF auth.uid() IS NULL OR auth.role()<>'authenticated' OR other_id IS NULL OR other_id=auth.uid() THEN
  RAISE EXCEPTION 'Invalid contact';
 END IF;
 INSERT INTO public.tichor_contact_requests(requester_id,recipient_id,status)
 VALUES(auth.uid(),other_id,'blocked')
 ON CONFLICT(requester_id,recipient_id) DO UPDATE SET status='blocked',updated_at=now();
END $$;

CREATE OR REPLACE FUNCTION public.tichor_contact_allowed(other_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path='' AS $$
 SELECT auth.uid() IS NOT NULL AND auth.role()='authenticated' AND other_id IS NOT NULL AND
 EXISTS(SELECT 1 FROM public.tichor_contact_requests r WHERE r.status='accepted' AND
 ((r.requester_id=auth.uid() AND r.recipient_id=other_id) OR (r.recipient_id=auth.uid() AND r.requester_id=other_id))) AND
 NOT EXISTS(SELECT 1 FROM public.tichor_contact_requests b WHERE b.status='blocked' AND
 ((b.requester_id=auth.uid() AND b.recipient_id=other_id) OR (b.recipient_id=auth.uid() AND b.requester_id=other_id)));
$$;

-- Remove UUID-returning email/phone/username lookup: it bypasses consent-based discovery.
REVOKE ALL ON FUNCTION public.find_tichor_user(text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.tichor_request_contact(text) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.tichor_respond_contact(uuid,text) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.tichor_contact_allowed(uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION public.tichor_block_contact(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.tichor_request_contact(text),public.tichor_respond_contact(uuid,text),public.tichor_contact_allowed(uuid),public.tichor_block_contact(uuid) TO authenticated;

-- PostgreSQL combines permissive policies with OR; old sender policies MUST be removed.
DROP POLICY IF EXISTS "sender inserts" ON public.chat_messages;
DROP POLICY IF EXISTS "sender inserts calls" ON public.tichor_call_events;
DROP POLICY IF EXISTS tichor_messages_consent_insert ON public.chat_messages;
DROP POLICY IF EXISTS tichor_calls_consent_insert ON public.tichor_call_events;
CREATE POLICY tichor_messages_consent_insert ON public.chat_messages FOR INSERT TO authenticated
 WITH CHECK(sender_id=auth.uid() AND public.tichor_contact_allowed(recipient_id));
CREATE POLICY tichor_calls_consent_insert ON public.tichor_call_events FOR INSERT TO authenticated
 WITH CHECK(sender_id=auth.uid() AND public.tichor_contact_allowed(recipient_id));
-- Fail closed if unexpected permissive INSERT policies exist.
DO $$
BEGIN
 IF EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public'
 AND tablename IN ('chat_messages','tichor_call_events') AND cmd IN ('INSERT','ALL')
 AND permissive='PERMISSIVE' AND policyname NOT IN ('tichor_messages_consent_insert','tichor_calls_consent_insert'))
 THEN RAISE EXCEPTION 'Unexpected permissive insert policies remain: review before deploying'; END IF;
END $$;
COMMIT;

-- AFTER MIGRATION: review profile lookup, storage attachments, call notifications,
-- guest access, RPC grants, and authentication settings. Test with two non-admin users.
