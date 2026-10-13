/**
 * Run `fn` over `items` with at most `limit` in flight. Results keep input order; a rejection only
 * affects its own slot.
 */
export async function mapBounded<T, R>(items: readonly T[], limit: number, fn: (item: T, index: number) => Promise<R>): Promise<PromiseSettledResult<R>[]> {
	const results: PromiseSettledResult<R>[] = new Array(items.length);
	let next = 0;
	async function worker(): Promise<void> {
		while (next < items.length) {
			const index = next++;
			try {
				results[index] = { status: "fulfilled", value: await fn(items[index]!, index) };
			} catch (reason) {
				results[index] = { status: "rejected", reason };
			}
		}
	}
	const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, () => worker());
	await Promise.all(workers);
	return results;
}
