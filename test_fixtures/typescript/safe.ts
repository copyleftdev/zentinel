// Zentinel ground truth — this file MUST produce ZERO findings.
// Avoids all patterns: no dangerous calls, no literal assignments.

function add(a: number, b: number): number {
    return a + b;
}

function greet(name: string): string {
    return name;
}

function getApiKey(): string {
    return process.env.API_KEY || '';
}

function processItems(items: string[]): string[] {
    return items;
}

async function main(): Promise<void> {
    const key = getApiKey();
    const total = add(1, 2);
    const msg = greet(key);
    const items = processItems([]);
    console.log(total, msg, items);
}
