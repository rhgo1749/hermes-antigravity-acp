# Terms, licensing, and attribution

This is documentation, not legal advice: the
authoritative text is always Google's current published terms for your
account and territory. Quotations below were re-checked on the official pages
on **2026-11-08**; if the pages have since changed, the pages win and this
document needs an update.

## 1. Personal Antigravity OAuth in third-party harnesses

Google's Antigravity Terms (https://antigravity.google/terms) state, in the
acceptable-use section:

> Using third party software, tools, or services to access the Service (e.g.
> using OpenClaw with Antigravity OAuth) is a breach of this Agreement. Such
> actions may be grounds for suspension or termination of your Antigravity
> and/or Gemini CLI accounts.

Google's Antigravity FAQ (https://www.antigravity.google/docs/faq/) answers
"Why can't I use third-party software (such as Claude Code, OpenClaw, or
OpenCode) with my Antigravity login?" with:

> Using third-party software, tools, or services to access Antigravity is a
> violation of our Terms of Service [...]. To use a third-party coding agent
> with Gemini, we recommend using a Gemini Enterprise or Google AI Studio
> API key.

And on headless/automation:

> Antigravity CLI headless mode (`agy -p`) is intended for direct scripting
> and CI workflows. Wrapping agy inside third-party coding agents or
> applications, or automating account rotation, is not supported under
> consumer plans.

**The inference boundary.** Google publishes the official standalone ACP
server, and it advertises auth methods `oauth-personal`, `oauth-business`,
`gemini-api-key`, and `agent-platform` in its unauthenticated `initialize`
response. That is the server's protocol surface; **it does not establish that
personal subscription OAuth is permitted through an external harness.**
Server capability and terms permission are separate questions, and for
individual Antigravity logins the terms answer is explicitly "no" for
third-party access.

## 2. What this project therefore does and does not do

- Does **not** present personal Google AI / Antigravity subscription quota as
  a third-party API substitute.
- Does **not** automate, extract, proxy, or emulate personal OAuth. All
  sign-in happens inside Google's official runtime; the plugin declares
  `requires_env: []` and holds no credentials.
- The default provider does not use a multi-account router. The optional MUX
  selects among configured accounts for new sessions and applies cooldowns
  after failures. Google's FAQ warns that automated account rotation is not
  supported under consumer plans; review the terms before enabling MUX and
  do not use it to evade quotas.
- Does **not** claim that a permitted-for-you route is permitted for
  everyone: organizational (Gemini Enterprise / workspace) routes depend on
  your administrator's access grant, and API-key routes are governed by the
  API terms attached to your key.

## 3. Routes Google's own documentation names for third-party clients

Only to the extent currently documented (accessed 2026-11-08):

1. **Gemini API key via Google AI Studio** — the FAQ's named recommendation
   for third-party coding agents; governed by the AI Studio / API terms that
   apply to your key.
2. **Gemini Enterprise (or applicable organizational) routes** — organization-
   managed; requires administrative access grants.
3. Whatever new path Google explicitly authorizes for your account and client
   in the future — this document will not anticipate one.

The official ACP server's advertised `gemini-api-key` and `agent-platform`
methods align with routes (1) and (2); authentication for them still happens
inside Google's runtime. Choosing among them, and confirming they are
permitted for your plan/territory/organization, is your decision against the
current official texts.

## 4. Verification status is separate from permission

Even where a route is permitted, credential-free CI does not establish live
authentication or model inference. A supervised one-prompt canary received a
response on an earlier client version; it does not establish current-release
end-to-end behavior or general permission for other uses. The clean-room
records (GitHub-hosted dedicated-UID, credential-free)
prove install/verify/unauthenticated-handshake mechanics only. See
`docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md` and
`docs/clean-env-e2e-smoke.md`.

## 5. Licensing and attribution

- **This repository's code:** MIT (`LICENSE`).
- **Google's `agy_acp_server` binaries and services:** proprietary, governed
  by Google's licenses and terms. This repository **does not redistribute
  them**; installation fetches them directly from `dl.google.com` with
  first-party publisher SHA-256 pins verified before extraction
  (`antigravity_acp/registry.py`). Provenance of the pinned server is that
  publisher path plus the pinned digests.
- **`NOTICE.md`** preserves three obligations, unchanged: (a) this is an
  independent project **not affiliated with Google**; (b) the MIT license text
  with copyright notice; (c) attribution that parts of the standalone
  ACP/OpenAI bridge and client behavior derive from **Hermes Agent by Nous
  Research** (MIT, Copyright (c) 2025 Nous Research), including its ACP
  transport and tool-bridge implementation.
- **ACP Registry:** the official registry entry for the server is
  https://github.com/agentclientprotocol/registry/tree/main/antigravity-acp
  (location re-checked 2026-11-08); this repository consumes the registry's
  published version/platform mapping, it is not the registry entry's owner.
- **Hermes plugin catalog:** submission-candidate design lives in
  `docs/plugin-catalog-entry.draft.yaml`; the catalog entry itself (and any
  external submission) requires separate approval. No catalog registration
  exists today.

## 6. Change management

Terms and catalog status are volatile. The README status table carries a
checked-date stamp for these claims; re-verify the official pages at delivery
time of any PR touching this file. If Google's terms change in a way that
materially affects sections 1–3, update those sections and the README terms
summary in the same change.
