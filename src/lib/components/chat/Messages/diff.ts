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
export type DiffSegment = { text: string; changed: boolean };
export type DiffRow = {
	type: 'file' | 'hunk' | 'addition' | 'deletion' | 'meta' | 'context';
	prefix: string;
	content: string;
	oldNumber: number | null;
	newNumber: number | null;
	segments: DiffSegment[];
};

export function parseDiffRows(code: string): DiffRow[] {
	let oldNumber = 0;
	let newNumber = 0;
	let oldRemaining = 0;
	let newRemaining = 0;
	const rows = code.split('\n').map((text): DiffRow => {
		const row: DiffRow = {
			type: 'context',
			prefix: '',
			content: text,
			oldNumber: null,
			newNumber: null,
			segments: []
		};
		const hunk = text.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
		const inHunk = oldRemaining > 0 || newRemaining > 0;
		if (hunk) {
			row.type = 'hunk';
			oldNumber = Number(hunk[1]);
			newNumber = Number(hunk[3]);
			oldRemaining = Number(hunk[2] ?? 1);
			newRemaining = Number(hunk[4] ?? 1);
		} else if (
			text.startsWith('diff ') ||
			(!inHunk &&
				/^(index |---(?:\s|$)|\+\+\+(?:\s|$)|(?:old|new|deleted file|new file) mode |(?:dis)?similarity index |(?:rename|copy) (?:from|to) )/.test(
					text
				))
		) {
			row.type = 'file';
			oldRemaining = newRemaining = 0;
		} else if (text.startsWith('@@')) {
			// Incomplete streaming headers must not inherit the preceding hunk's numbers.
			row.type = 'hunk';
			oldRemaining = newRemaining = 0;
		} else if (text.startsWith('\\')) {
			row.type = 'meta';
		} else {
			if (text.startsWith('+')) row.type = 'addition';
			if (text.startsWith('-')) row.type = 'deletion';
			if (/^[+\- ]/.test(text)) {
				row.prefix = text[0];
				row.content = text.slice(1);
			}
			if (inHunk && (row.prefix || text === '')) {
				if (row.type !== 'addition' && oldRemaining > 0) {
					row.oldNumber = oldNumber++;
					oldRemaining--;
				}
				if (row.type !== 'deletion' && newRemaining > 0) {
					row.newNumber = newNumber++;
					newRemaining--;
				}
			}
		}
		row.segments = [{ text: row.content, changed: false }];
		void gr_check(row, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return row;
	});

	for (let i = 0; i < rows.length; ) {
		const removed: DiffRow[] = [];
		const added: DiffRow[] = [];
		while (rows[i]?.type === 'deletion' || rows[i]?.type === 'addition') {
			(rows[i].type === 'deletion' ? removed : added).push(rows[i++]);
		}
		if (removed.length === added.length) {
			removed.forEach((oldRow, index) => emphasizePair(oldRow, added[index]));
		}
		i++;
	}
	void gr_check(rows, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return rows;
}

function emphasizePair(oldRow: DiffRow, newRow: DiffRow) {
	if (
		oldRow.content === newRow.content ||
		Math.max(oldRow.content.length, newRow.content.length) >= 1024
	)
		return;
	const oldText = Array.from(oldRow.content);
	const newText = Array.from(newRow.content);
	let start = 0;
	while (start < Math.min(oldText.length, newText.length) && oldText[start] === newText[start])
		start++;
	let oldEnd = oldText.length;
	let newEnd = newText.length;
	while (oldEnd > start && newEnd > start && oldText[oldEnd - 1] === newText[newEnd - 1]) {
		oldEnd--;
		newEnd--;
	}
	// ponytail: like computer's Git view, emphasize one changed middle per paired line.
	// Use a token diff if multiple independent edits need separate spans.
	for (const [row, text, end] of [
		[oldRow, oldText, oldEnd],
		[newRow, newText, newEnd]
	] as const) {
		row.segments = [
			{ text: text.slice(0, start).join(''), changed: false },
			{ text: text.slice(start, end).join(''), changed: true },
			{ text: text.slice(end).join(''), changed: false }
		].filter((segment) => segment.text.length > 0);
	}
}
