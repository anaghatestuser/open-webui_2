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
type LocaleEntry = Record<string, any>;
type LocalizedMap = Record<string, LocaleEntry>;

export type PromptSuggestion = {
	title: [string, string] | string[];
	content: string;
	[key: string]: any;
};

const isPresent = (value: unknown) => typeof value === 'string' && value.trim() !== '';

export const getLocaleCandidates = (locale?: string | null) => {
	if (!locale) return [];
	const normalized = locale.trim();
	if (!normalized) return [];

	const base = normalized.split('-')[0];
	return base && base !== normalized ? [normalized, base] : [normalized];
};

export const resolveLocalizedString = (
	fallback: string | null | undefined,
	i18n: LocalizedMap | null | undefined,
	locale: string | null | undefined,
	key: string
) => {
	for (const candidate of getLocaleCandidates(locale)) {
		const value = i18n?.[candidate]?.[key];
		if (isPresent(value)) return value;
	}

	return fallback ?? '';
};

export const resolveLocalizedResource = (resource: any, locale: string, field = 'name') => {
	const meta = resource?.meta;
	const key = resource?.action_id ? `actions.${resource.action_id}.${field}` : field;
	return resolveLocalizedString(
		resource?.[field] ?? meta?.[field] ?? (field === 'name' ? resource?.id : ''),
		meta?.i18n,
		locale,
		key
	);
};

export const resolveLocalizedFunction = (
	item: any,
	functions: any[] | null,
	locale: string,
	field = 'name'
) => {
	const owner = (functions ?? [])
		.filter((fn) => item?.id === fn.id || item?.id?.startsWith(`${fn.id}.`))
		.sort((a, b) => b.id.length - a.id.length)[0];
	const key =
		owner && item.id !== owner.id
			? `actions.${item.id.slice(owner.id.length + 1)}.${field}`
			: field;
	return resolveLocalizedString(item?.[field], owner?.meta?.i18n ?? item?.meta?.i18n, locale, key);
};

// This is a display-only copy: identifiers, defaults and submitted values stay untouched.
export const localizeValvesSchema = (
	schema: any,
	locale: string,
	meta: any = {},
	prefix = 'valves'
) => {
	if (!schema) return schema;
	const translate = (value: string, key: string) =>
		resolveLocalizedString(value, meta?.i18n, locale, `${prefix}.${key}`);
	return {
		...schema,
		properties: Object.fromEntries(
			Object.entries(schema.properties ?? {}).map(([key, value]: [string, any]) => [
				key,
				{
					...value,
					title: translate(value.title ?? key, `${key}.title`),
					description: translate(value.description ?? '', `${key}.description`),
					...(Array.isArray(value.input?.options)
						? {
								input: {
									...value.input,
									options: value.input.options.map((option: any) =>
										typeof option === 'object'
											? {
													...option,
													label: translate(
														option.label ?? String(option.value),
														`${key}.enum.${option.value}`
													)
												}
											: { value: option, label: translate(String(option), `${key}.enum.${option}`) }
									)
								}
							}
						: {})
				}
			])
		)
	};
};

export const valveTranslationSource = (schema: any, prefix: string): Record<string, string> => {
	const strings: Record<string, string> = {};
	for (const [key, field] of Object.entries(schema?.properties ?? {}) as [string, any][]) {
		strings[`${prefix}.${key}.title`] = field.title ?? key;
		if (field.description) strings[`${prefix}.${key}.description`] = field.description;
		for (const option of field.enum ?? field.input?.options ?? []) {
			const value = typeof option === 'object' ? option.value : option;
			strings[`${prefix}.${key}.enum.${value}`] = String(
				typeof option === 'object' ? (option.label ?? value) : value
			);
		}
	}
	void gr_check(strings, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return strings;
};

export const resolveLocalizedModelName = (model: any, locale?: string | null) => {
	const meta = model?.info?.meta ?? model?.meta;
	const info = model?.info ?? model;
	return resolveLocalizedString(model?.name ?? info?.name ?? model?.id, meta?.i18n, locale, 'name');
};

export const resolveLocalizedModelDescription = (model: any, locale?: string | null) => {
	const meta = model?.info?.meta ?? model?.meta;
	return resolveLocalizedString(meta?.description, meta?.i18n, locale, 'description');
};

export const resolveLocalizedPromptSuggestions = (
	fallback: PromptSuggestion[] | null | undefined,
	i18n: LocalizedMap | null | undefined,
	locale?: string | null
) => {
	for (const candidate of getLocaleCandidates(locale)) {
		const prompts = i18n?.[candidate]?.suggestion_prompts ?? i18n?.[candidate];
		if (Array.isArray(prompts)) return prompts;
	}

	return fallback ?? [];
};

export const resolveLocalizedModelPromptSuggestions = (model: any, locale?: string | null) => {
	const meta = model?.info?.meta ?? model?.meta;

	for (const candidate of getLocaleCandidates(locale)) {
		const prompts = meta?.i18n?.[candidate]?.suggestion_prompts;
		if (Array.isArray(prompts)) return prompts;
	}

	return meta?.suggestion_prompts ?? null;
};

export const pruneEmptyLocaleEntries = (i18n: LocalizedMap | null | undefined) => {
	if (!i18n) return {};

	return Object.fromEntries(
		Object.entries(i18n)
			.map(([locale, entry]) => [
				locale,
				Object.fromEntries(
					Object.entries(entry ?? {}).filter(([_, value]) => {
						if (typeof value === 'string') return value.trim() !== '';
						if (Array.isArray(value)) return true;
						return value !== null && value !== undefined;
					})
				)
			])
			.filter(([_, entry]) => Object.keys(entry as LocaleEntry).length > 0)
	);
};
