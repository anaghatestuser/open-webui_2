// Copyright (c) Lineaje, Inc. All rights reserved.
// Lineaje guardrail helper — inlined once per file (see _import_hint); no npm
// package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce" and fails
// open (returns `data` unchanged) unless a policy deliberately blocks it
// (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
type GrEnv = Record<string, string | undefined>;
const _env: GrEnv = ((globalThis as any).process?.env ?? {}) as GrEnv; // Lineaje: env lookup shim (works in Node and browser bundles)

export class GRBlockedError extends Error {
  policyId: string;
  reason: string;

  constructor(policyId: string, reason: string) {
    super(`Guardrail block for policy '${policyId}': ${reason}`);
    this.name = "GRBlockedError";
    this.policyId = policyId;
    this.reason = reason;
  }
}

export async function gr_check(
  data: unknown,
  sourceType: string,
  destinationType: string,
  tenantId: string = "",
  timeoutMs: number = 5000,
  context: Record<string, string | undefined> = {},
): Promise<unknown> {
  const url = _env["GR_SERVICE_URL"] || "";
  if (!url) {
    return data; // fail-open: GR_SERVICE_URL not configured
  }

  const tid = tenantId || _env["GR_TENANT_ID"] || "";
  const bearer = _env["GR_BEARER_TOKEN"] || _env["LINEAJE_PAT_TOKEN"] || _env["LINEAJE_PAT"] || "";
  const hopLabel = `${sourceType}->${destinationType}`;
  const paramsKey = destinationType === "agent" ? "out_params" : "in_params";

  const body: Record<string, unknown> = {
    source_type: sourceType,
    destination_type: destinationType,
    [paramsKey]: { data },
  };
  for (const [k, v] of Object.entries(context)) {
    if (v) {
      body[k] = v;
    }
  }
  if (tid) {
    body["tenant_id"] = tid;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let resp: Response;
  try {
    resp = await fetch(url.replace(/\/+$/, "") + "/enforce", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + bearer,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 403) {
    let detail: any = {};
    try {
      const errBody: any = await resp.json();
      detail = errBody?.detail ?? {};
    } catch {
      detail = {};
    }
    const blockedBy = detail.blocked_by ?? [];
    const policyId = blockedBy[0]?.policy_id ?? "unknown";
    const reason = detail.message ?? "Request denied by policy enforcement.";
    console.warn(
      `gr_client[${hopLabel}]: BLOCKED by policy=${policyId} — ${reason}`,
    );
    if ((_env["GR_BLOCK_MODE"] || "enforce").toLowerCase() === "audit") {
      return data;
    }
    throw new GRBlockedError(policyId, reason);
  }

  if (!resp.ok) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (HTTP ${resp.status}) — failing open`,
    );
    return data;
  }

  let result: any;
  try {
    result = await resp.json();
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  }

  if (result?.status === "escalate") {
    console.warn(
      `gr_client[${hopLabel}]: escalation flagged — passing through for human review`,
    );
  }

  return result?.result?.data ?? data;
}
export const placeholders = (text: string) =>
	[
		...new Set(
			Array.from(text.matchAll(/\{\{\s*-?\s*([^},]+)(?:,[^}]+)?\s*\}\}/g), (match) =>
				match[1].trim()
			)
		)
	].sort();

export const validateDictionary = (
	value: unknown,
	source: Record<string, string> = {}
): Record<string, string> => {
	if (!value || typeof value !== 'object' || Array.isArray(value))
		throw new Error('Expected a JSON object of translation keys and strings.');
	for (const [key, text] of Object.entries(value)) {
		if (!key.trim() || unsafeKeys.has(key)) throw new Error(`Invalid translation key: ${key}`);
		if (typeof text !== 'string') throw new Error(`Translation must be a string: ${key}`);
		if (
			text.trim() &&
			JSON.stringify(placeholders(source[key] || key)) !== JSON.stringify(placeholders(text))
		)
			throw new Error(`Interpolation placeholders do not match: ${key}`);
	}
	return value as Record<string, string>;
};

export const validateI18n = (value: I18nOverrides): I18nOverrides => {
	const cleaned: I18nOverrides = {};
	for (const [locale, entries] of Object.entries(value)) {
		if (!locale.trim() || unsafeKeys.has(locale)) throw new Error(`Invalid language: ${locale}`);
		const dictionary = validateDictionary(entries);
		const nonempty = Object.fromEntries(
			Object.entries(dictionary).filter(([, text]) => text.trim())
		);
		if (Object.keys(nonempty).length) cleaned[locale] = nonempty;
	}
	void gr_check(cleaned, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return cleaned;
};
export type I18nOverrides = Record<string, Record<string, string>>;
export type I18nEntry = { content: string; i18n: I18nOverrides };

export const i18nToEntries = (value: I18nOverrides): I18nEntry[] => {
	const entries = new Map<string, I18nEntry>();
	for (const [locale, dictionary] of Object.entries(value)) {
		for (const [content, translation] of Object.entries(dictionary)) {
			if (!entries.has(content)) entries.set(content, { content, i18n: {} });
			entries.get(content)!.i18n[locale] = { content: translation };
		}
	}
	return [...entries.values()];
};

export const entriesToI18n = (entries: I18nEntry[]): I18nOverrides => {
	const value: I18nOverrides = {};
	const seen = new Set<string>();
	for (const entry of entries) {
		const translations = Object.entries(entry.i18n).filter(([, text]) => text.content.trim());
		if (!entry.content.trim()) {
			if (translations.length) throw new Error('Original text is required for translated rows.');
			continue;
		}
		if (seen.has(entry.content)) throw new Error(`Duplicate original text: ${entry.content}`);
		seen.add(entry.content);
		validateDictionary({ [entry.content]: '' });
		for (const [locale, translation] of translations) {
			value[locale] = { ...value[locale], [entry.content]: translation.content };
		}
	}
	return validateI18n(value);
};

const unsafeKeys = new Set(['__proto__', 'prototype', 'constructor']);
