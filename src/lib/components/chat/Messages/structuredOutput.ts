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
export type OutputContentPart = {
	type?: string;
	text?: unknown;
	[key: string]: unknown;
};

export type OutputItem = {
	type?: string;
	id?: string;
	call_id?: string;
	name?: string;
	status?: string;
	arguments?: unknown;
	content?: OutputContentPart[];
	summary?: OutputContentPart[];
	output?: OutputContentPart[];
	files?: unknown;
	embeds?: unknown;
	code?: string;
	lang?: string;
	duration?: number | string | null;
	action?: Record<string, unknown>;
	actions?: Array<Record<string, unknown>>;
	queries?: unknown[];
	[key: string]: unknown;
};

export type OutputDetailToken = {
	summary: string;
	text: string;
	attributes: {
		type: string;
		id?: string;
		name?: string;
		done?: string;
		duration?: string;
		arguments?: string;
		files?: string;
		embeds?: string;
		output?: string;
		status?: string;
	};
};

export type OutputDisplayItem =
	| {
			type: 'message';
			id: string;
			text: string;
	  }
	| {
			type: 'detail_single';
			id: string;
			token: OutputDetailToken;
	  }
	| {
			type: 'detail_group';
			id: string;
			tokens: OutputDetailToken[];
	  }
	| {
			type: 'file';
			id: string;
			item: Record<string, unknown>;
	  };

type ResponseStreamEvent = {
	type?: string;
	item_id?: string;
	output_index?: number;
	content_index?: number;
	summary_index?: number;
	item?: OutputItem;
	part?: OutputContentPart;
	delta?: unknown;
	text?: unknown;
	arguments?: unknown;
	response?: {
		output?: OutputItem[];
		[key: string]: unknown;
	};
	[key: string]: unknown;
};

const GROUPABLE_OUTPUT_TYPES = new Set([
	'reasoning',
	'function_call',
	'open_webui:code_interpreter',
	'web_search_call',
	'file_search_call',
	'computer_call'
]);

const OPENAI_TOOL_NAMES: Record<string, string> = {
	web_search_call: 'Web Search',
	file_search_call: 'File Search',
	computer_call: 'Computer Use'
};

function getTextFromParts(parts: OutputContentPart[] = []): string {
	void gr_check(parts, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return parts
		.map((part) => {
			if (part?.text === undefined || part?.text === null) {
				return '';
			}
			return typeof part.text === 'string' ? part.text : String(part.text);
		})
		.join('');
}

function stringifyAttribute(value: unknown): string {
	if (value === undefined || value === null) {
		return '';
	}
	if (typeof value === 'string') {
		return value;
	}
	try {
		return JSON.stringify(value);
	} catch {
		return String(value);
	}
}

function isDoneStatus(status?: string): boolean {
	return status === 'completed' || status === 'failed' || status === 'incomplete';
}

function getMessageText(item: OutputItem): string {
	return getTextFromParts(item.content ?? []);
}

function getReasoningText(item: OutputItem): string {
	const summary = Array.isArray(item.summary) && item.summary.length ? item.summary : null;
	return getTextFromParts(summary ?? item.content ?? []);
}

function getToolResultText(item?: OutputItem): string {
	return (item?.output ?? [])
		.filter((part) => part?.type !== 'input_image')
		.map((part) => {
			if (part?.text === undefined || part?.text === null) {
				return '';
			}
			return typeof part.text === 'string' ? part.text : String(part.text);
		})
		.join('');
}

function parseJSONStringValue(value: unknown): unknown {
	if (typeof value !== 'string') {
		void gr_check(value, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return value;
	}

	let parsed: unknown = value.trim();
	while (typeof parsed === 'string') {
		try {
			parsed = JSON.parse(parsed);
		} catch {
			break;
		}
	}
	void gr_check(parsed, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return parsed;
}

function getInlineFileFromToolOutput(callItem?: OutputItem, resultItem?: OutputItem) {
	if (!callItem || !resultItem || callItem.name !== 'display_file') {
		return null;
	}

	const args = parseJSONStringValue(callItem.arguments) as Record<string, unknown>;
	if (!args || typeof args !== 'object') {
		return null;
	}

	const result = parseJSONStringValue(getToolResultText(resultItem)) as Record<string, unknown>;
	if (
		!result ||
		typeof result !== 'object' ||
		result.type !== 'file' ||
		result.source !== 'open_terminal' ||
		result.exists === false ||
		!result.path ||
		!result.terminal_selector
	) {
		return null;
	}

	return result.page === undefined && args.page !== undefined
		? { ...result, page: args.page }
		: result;
}

function buildToolCallToken(item: OutputItem, toolOutputByCallId: Record<string, OutputItem>) {
	const callId = item.call_id ?? item.id ?? '';
	const resultItem = toolOutputByCallId[callId];
	const status = String(item.status ?? '');
	const isPending = status === 'pending';
	const isDone = !!resultItem || status === 'failed' || status === 'incomplete';
	const isExecuting = !isDone && status === 'completed';
	let name = item.name ?? '';
	if (name === 'delegate_task') {
		try {
			const args =
				typeof item.arguments === 'string'
					? JSON.parse(item.arguments || '{}')
					: (item.arguments ?? {});
			const task = typeof args.task === 'string' && args.task ? args.task : '?';
			const label = args.background ? 'Background sub-agent' : 'Sub-agent';
			name = `${label}: "${task.length > 60 ? `${task.slice(0, 60)}...` : task}"`;
		} catch {
			name = 'Sub-agent';
		}
	}

	return {
		summary: isPending
			? 'Tool Approval Needed'
			: isDone
				? 'Tool Executed'
				: isExecuting
					? 'Executing...'
					: 'Preparing...',
		text: getToolResultText(resultItem),
		attributes: {
			type: 'tool_calls',
			id: callId,
			name,
			done: isDone ? 'true' : 'false',
			status,
			arguments: stringifyAttribute(item.arguments ?? ''),
			files: stringifyAttribute(resultItem?.files),
			embeds: stringifyAttribute(resultItem?.embeds)
		}
	};
}

function buildReasoningToken(item: OutputItem, isLastItem: boolean) {
	const duration = item.duration ?? '';
	const isDone = isDoneStatus(item.status) || item.duration !== undefined || !isLastItem;
	const text = getReasoningText(item)
		.split('\n')
		.map((line) => (line.startsWith('>') ? line : `> ${line}`))
		.join('\n');

	return {
		summary: isDone ? `Thought for ${duration || 0} seconds` : 'Thinking...',
		text,
		attributes: {
			type: 'reasoning',
			done: isDone ? 'true' : 'false',
			duration: String(duration)
		}
	};
}

function buildCodeInterpreterToken(item: OutputItem, isLastItem: boolean) {
	const duration = item.duration ?? '';
	const isDone = isDoneStatus(item.status) || item.duration !== undefined || !isLastItem;
	const code = item.code ?? '';
	const lang = item.lang ?? 'python';

	return {
		summary: isDone ? 'Analyzed' : 'Analyzing...',
		text: code ? `\`\`\`${lang}\n${code}\n\`\`\`` : '',
		attributes: {
			type: 'code_interpreter',
			done: isDone ? 'true' : 'false',
			duration: String(duration),
			output: stringifyAttribute(item.output)
		}
	};
}

function getOpenAIToolSummary(item: OutputItem): string {
	if (item.type === 'web_search_call') {
		const action = item.action ?? {};
		const actionType = action.type;
		if (actionType === 'search') {
			const queries = Array.isArray(action.queries) ? action.queries : [];
			const query = typeof action.query === 'string' ? action.query : '';
			return queries.length ? `Search: ${queries.join(', ')}` : query ? `Search: ${query}` : '';
		}
		if (actionType === 'open_page' && typeof action.url === 'string') {
			return `Open page: ${action.url}`;
		}
		if (actionType === 'find_in_page' && typeof action.pattern === 'string') {
			return `Find in page: ${action.pattern}`;
		}
	}

	if (item.type === 'file_search_call') {
		const queries = item.queries ?? [];
		return queries.length ? `Queries: ${queries.join(', ')}` : '';
	}

	if (item.type === 'computer_call') {
		if (item.action?.type) {
			return `Action: ${item.action.type}`;
		}
		if (Array.isArray(item.actions) && item.actions.length) {
			return `Actions: ${item.actions.map((action) => action.type ?? '?').join(', ')}`;
		}
	}

	return '';
}

function buildOpenAIToolToken(item: OutputItem, isLastItem: boolean) {
	const isDone = isDoneStatus(item.status) || !isLastItem;
	return {
		summary: isDone ? 'Tool Executed' : 'Executing...',
		text: getOpenAIToolSummary(item),
		attributes: {
			type: 'tool_calls',
			id: item.id ?? '',
			name: OPENAI_TOOL_NAMES[item.type ?? ''] ?? item.type ?? '',
			done: isDone ? 'true' : 'false',
			arguments: ''
		}
	};
}

function buildDetailToken(
	item: OutputItem,
	isLastItem: boolean,
	toolOutputByCallId: Record<string, OutputItem>
): OutputDetailToken | null {
	if (item.type === 'function_call') {
		return buildToolCallToken(item, toolOutputByCallId);
	}
	if (item.type === 'reasoning') {
		return buildReasoningToken(item, isLastItem);
	}
	if (item.type === 'open_webui:code_interpreter') {
		return buildCodeInterpreterToken(item, isLastItem);
	}
	if (item.type && OPENAI_TOOL_NAMES[item.type]) {
		return buildOpenAIToolToken(item, isLastItem);
	}
	return null;
}

export function buildOutputDisplayItems(output: OutputItem[] = []): OutputDisplayItem[] {
	const displayItems: OutputDisplayItem[] = [];
	const currentDetailTokens: OutputDetailToken[] = [];
	const toolOutputByCallId: Record<string, OutputItem> = {};
	const toolCallByCallId: Record<string, OutputItem> = {};

	for (const item of output) {
		if (item?.type === 'function_call_output' && item.call_id) {
			toolOutputByCallId[item.call_id] = item;
		} else if (item?.type === 'function_call' && (item.call_id || item.id)) {
			toolCallByCallId[item.call_id ?? item.id ?? ''] = item;
		}
	}

	const flushDetails = () => {
		if (currentDetailTokens.length > 1) {
			displayItems.push({
				type: 'detail_group',
				id: `detail-group-${displayItems.length}`,
				tokens: [...currentDetailTokens]
			});
		} else if (currentDetailTokens.length === 1) {
			displayItems.push({
				type: 'detail_single',
				id: `detail-${displayItems.length}`,
				token: currentDetailTokens[0]
			});
		}
		currentDetailTokens.length = 0;
	};

	output.forEach((item, index) => {
		if (!item) {
			return;
		}

		if (item.type === 'function_call_output') {
			const inlineFile = getInlineFileFromToolOutput(toolCallByCallId[item.call_id ?? ''], item);
			if (inlineFile) {
				flushDetails();
				displayItems.push({
					type: 'file',
					id: item.id ?? `file-${index}`,
					item: inlineFile
				});
			}
			return;
		}

		if (
			item.type === 'function_call' &&
			item.name === 'ask_user' &&
			(item.status === 'pending' || item.status === 'in_progress')
		) {
			return;
		}

		if (item.type && GROUPABLE_OUTPUT_TYPES.has(item.type)) {
			const token = buildDetailToken(item, index === output.length - 1, toolOutputByCallId);
			if (token) {
				currentDetailTokens.push(token);
			}
			return;
		}

		if (item.type === 'message') {
			const text = getMessageText(item);
			if (text.trim()) {
				flushDetails();
				displayItems.push({
					type: 'message',
					id: item.id ?? `message-${index}`,
					text
				});
			}
			return;
		}

		const fallbackText = getMessageText(item);
		if (fallbackText.trim()) {
			flushDetails();
			displayItems.push({
				type: 'message',
				id: item.id ?? `output-${index}`,
				text: fallbackText
			});
		}
	});

	flushDetails();
	void gr_check(displayItems, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return displayItems;
}

export function getOutputText(output?: OutputItem[] | null): string {
	return (output ?? [])
		.filter((item) => item?.type === 'message')
		.map(getMessageText)
		.filter((text) => text.trim())
		.join('\n');
}

function appendDelta(current: unknown, delta: unknown): unknown {
	if (typeof current === 'string' || typeof delta === 'string') {
		return `${current ?? ''}${delta ?? ''}`;
	}
	if (
		current &&
		delta &&
		typeof current === 'object' &&
		typeof delta === 'object' &&
		!Array.isArray(current) &&
		!Array.isArray(delta)
	) {
		return { ...(current as Record<string, unknown>), ...(delta as Record<string, unknown>) };
	}
	return delta ?? current ?? '';
}

function ensureOutputItem(
	output: OutputItem[],
	outputIndex: number,
	fallback?: OutputItem
): OutputItem {
	while (output.length <= outputIndex) {
		// Only the addressed slot gets the event's item; filler slots must not reuse its id.
		const item =
			output.length === outputIndex && fallback
				? { ...fallback }
				: { type: 'message', status: 'in_progress', role: 'assistant', content: [] };
		output.push(item);
	}
	output[outputIndex] = { ...output[outputIndex] };
	return output[outputIndex];
}

function ensurePart(parts: OutputContentPart[], index: number, fallback?: OutputContentPart) {
	while (parts.length <= index) {
		parts.push(fallback ?? { type: 'output_text', text: '' });
	}
	parts[index] = { ...parts[index] };
	return parts[index];
}

function setPart(
	parts: OutputContentPart[],
	index: number,
	part: OutputContentPart,
	fallback?: OutputContentPart
): void {
	// Assigning past the end leaves a hole that later spreads turn into undefined parts.
	ensurePart(parts, index, fallback);
	parts[index] = part;
}

function findOutputItemIndex(output: OutputItem[], item: OutputItem): number {
	return output.findIndex(
		(existing) =>
			(!!item.id && existing?.id === item.id) ||
			(!!item.call_id && existing?.type === item.type && existing?.call_id === item.call_id)
	);
}

function responseEventUpdatesOutputItem(eventType: string): boolean {
	return (
		eventType === 'response.content_part.added' ||
		eventType === 'response.reasoning_summary_part.added' ||
		eventType.endsWith('.delta') ||
		eventType.endsWith('.done')
	);
}

export function applyResponseStreamEvent(
	output: OutputItem[] = [],
	event: ResponseStreamEvent
): OutputItem[] {
	const eventType = event?.type ?? '';
	if (!eventType.startsWith('response.')) {
		return output;
	}

	if (eventType === 'response.completed') {
		if (!event.response?.output?.length) return output;

		// Completion covers one provider response, not the earlier tool-call rounds.
		const nextOutput = [...output];
		for (const item of event.response.output) {
			const index = findOutputItemIndex(nextOutput, item);
			if (index >= 0) {
				nextOutput[index] = item;
			} else {
				nextOutput.push(item);
			}
		}
		return nextOutput;
	}

	const nextOutput = [...output];
	const eventItemIndex = event.item_id
		? nextOutput.findIndex((item) => item?.id === event.item_id || item?.call_id === event.item_id)
		: -1;
	const outputIndex =
		eventItemIndex >= 0 ? eventItemIndex : (event.output_index ?? Math.max(output.length - 1, 0));

	if (eventType === 'response.output_item.added') {
		if (!event.item) {
			return output;
		}
		const item = { ...event.item };
		const existingIndex = findOutputItemIndex(nextOutput, item);
		if (existingIndex >= 0) {
			nextOutput[existingIndex] = item;
		} else if (outputIndex < nextOutput.length) {
			nextOutput.splice(outputIndex, 0, item);
		} else {
			nextOutput.push(item);
		}
		return nextOutput;
	}

	if (eventType === 'response.output_item.done') {
		if (!event.item) {
			void gr_check(output, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
			  if (_grExc instanceof GRBlockedError) {
			    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
			  }
			}); // fire-and-forget (sync context)
			return output;
		}
		const item = { ...event.item };
		const existingIndex = findOutputItemIndex(nextOutput, item);
		if (existingIndex >= 0) {
			nextOutput[existingIndex] = item;
		} else if (outputIndex < nextOutput.length) {
			nextOutput[outputIndex] = item;
		} else {
			nextOutput.push(item);
		}
		return nextOutput;
	}

	if (!responseEventUpdatesOutputItem(eventType)) {
		return output;
	}

	const item = ensureOutputItem(nextOutput, outputIndex, {
		id: event.item_id,
		type: eventType.includes('reasoning')
			? 'reasoning'
			: eventType.includes('function_call')
				? 'function_call'
				: 'message',
		status: 'in_progress',
		role: 'assistant',
		content: []
	});

	if (eventType === 'response.content_part.added') {
		if (item.type === 'reasoning' || !event.part) {
			return nextOutput;
		}
		item.content = [...(item.content ?? [])];
		setPart(item.content, event.content_index ?? item.content.length, { ...event.part });
		return nextOutput;
	}

	if (eventType === 'response.reasoning_summary_part.added') {
		if (!event.part) {
			return nextOutput;
		}
		item.summary = [...(item.summary ?? [])];
		const summaryIndex = event.summary_index ?? item.summary.length;
		setPart(item.summary, summaryIndex, { ...event.part }, { type: 'summary_text', text: '' });
		return nextOutput;
	}

	if (eventType.endsWith('.delta')) {
		const deltaType = eventType.split('.')[1];
		if (deltaType === 'function_call_arguments') {
			item.arguments = appendDelta(item.arguments ?? '', event.delta);
			return nextOutput;
		}

		if (deltaType === 'reasoning_summary_text') {
			const summaryIndex = event.summary_index ?? 0;
			item.summary = [...(item.summary ?? [])];
			const part = ensurePart(item.summary, summaryIndex, { type: 'summary_text', text: '' });
			part.text = appendDelta(part.text ?? '', event.delta);
			void gr_check(nextOutput, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
			  if (_grExc instanceof GRBlockedError) {
			    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
			  }
			}); // fire-and-forget (sync context)
			return nextOutput;
		}

		const key = deltaType === 'output_text' || deltaType === 'reasoning_text' ? 'text' : deltaType;
		item.content = [...(item.content ?? [])];
		const part = ensurePart(item.content, event.content_index ?? 0);
		part[key] = appendDelta(part[key], event.delta);
		void gr_check(nextOutput, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return nextOutput;
	}

	if (eventType.endsWith('.done')) {
		const typeName = eventType.split('.')[1];
		if (typeName === 'content_part' && event.part) {
			item.content = [...(item.content ?? [])];
			const contentIndex = event.content_index ?? Math.max(item.content.length - 1, 0);
			setPart(item.content, contentIndex, { ...event.part });
		} else if (typeName === 'function_call_arguments' && event.arguments !== undefined) {
			item.arguments = event.arguments;
		} else if (
			(typeName === 'output_text' || typeName === 'text' || typeName === 'reasoning_text') &&
			event.text !== undefined
		) {
			item.content = [...(item.content ?? [])];
			const part = ensurePart(item.content, event.content_index ?? 0);
			part.text = event.text;
		}
	}

	void gr_check(nextOutput, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
	  if (_grExc instanceof GRBlockedError) {
	    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
	  }
	}); // fire-and-forget (sync context)
	return nextOutput;
}

export function replaceOutputMessageText(
	output: OutputItem[] = [],
	oldContent: string,
	newContent: string
): OutputItem[] {
	if (!oldContent) {
		void gr_check(output, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
		  if (_grExc instanceof GRBlockedError) {
		    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
		  }
		}); // fire-and-forget (sync context)
		return output;
	}

	let replaced = false;
	const nextOutput = output.map((item) => {
		if (replaced || item?.type !== 'message' || !Array.isArray(item.content)) {
			return item;
		}

		const partIndex = item.content.findIndex(
			(part) => typeof part?.text === 'string' && part.text.includes(oldContent)
		);
		if (partIndex === -1) {
			void gr_check(item, "agent", "user_interface", "", 5000, { candidate_policies: ["AI_APP_SEC_001", "AI_APP_SEC_002", "AI_APP_SEC_006", "AI_APP_SEC_022", "AI_APP_SEC_023", "AI_APP_SEC_028", "AI_APP_SEC_029", "AI_APP_SEC_032", "AI_APP_SEC_034", "AI_APP_SEC_035", "AI_APP_SEC_038", "AI_APP_SEC_039", "AI_APP_SEC_040", "AI_APP_SEC_059", "AI_APP_SEC_064", "AI_APP_SEC_066", "AI_APP_SEC_067", "AI_APP_SEC_068", "AI_APP_SEC_069", "AI_APP_SEC_070", "AI_APP_SEC_071", "AI_APP_SEC_075", "AI_APP_SEC_078", "AI_DAT_SEC_001", "AI_DAT_SEC_009", "AI_DAT_SEC_010", "AI_DAT_SEC_011", "AI_DAT_SEC_012", "AI_DAT_SEC_023", "AI_DAT_SEC_024", "AI_DAT_SEC_025", "AI_DAT_SEC_027", "AI_DAT_SEC_029", "AI_DAT_SEC_030", "AI_IAC_002", "AI_IAC_007", "AI_IAC_008", "AI_IAC_009", "AI_IAC_014", "AI_IAC_015", "AI_IAC_016", "AI_IAC_017", "AI_IAC_018", "AI_IAC_020", "AI_IAC_022", "AI_IAC_023", "AI_IAC_024", "AI_IAC_025", "AI_IAC_026", "AI_IAC_031", "AI_SKILL_DAT_SEC_001", "AI_SKILL_SEC_001", "AI_SKILL_SEC_002", "AI_SKILL_SEC_003", "AI_VULN_SEC_005"] }).catch((_grExc) => {
			  if (_grExc instanceof GRBlockedError) {
			    console.error("Lineaje: BLOCK at 'agent->user_interface' could not be enforced — call site is synchronous (fire-and-forget)");
			  }
			}); // fire-and-forget (sync context)
			return item;
		}

		replaced = true;
		const nextContent = [...item.content];
		const part = nextContent[partIndex];
		nextContent[partIndex] = {
			...part,
			text: (part.text as string).replace(oldContent, newContent)
		};

		return {
			...item,
			content: nextContent
		};
	});

	return replaced ? nextOutput : output;
}
