/** C0 and C1 control characters other than tab and newline: a terminal reads them as escape sequences. */
const CONTROL_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

export function hasControlChars(text: string): boolean {
	return text.search(CONTROL_CHARS) >= 0;
}

/**
 * Text that agents wrote or quoted from the audited repository, with control characters made visible.
 * Shown in a terminal (or a report printed in one), an escape sequence could write the clipboard, plant
 * a hidden link, or overwrite other parts of the output.
 */
export function stripControl(text: string): string {
	return text.replace(/\r\n/g, "\n").replace(CONTROL_CHARS, "\uFFFD");
}

/** A code fence longer than any backtick run in `text`, so no line of the text can close it. */
export function fence(text: string, language = ""): string {
	const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((match) => match[0].length));
	const ticks = "`".repeat(longest + 1);
	return `${ticks}${language}\n${text.trimEnd()}\n${ticks}`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
	return `${count} ${count === 1 ? one : many}`;
}
