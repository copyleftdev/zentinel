// Zentinel ground truth — this file MUST produce ZERO findings.
// Avoids all patterns: no dangerous calls, no literal assignments.
const path = require('path');

function add(a, b) {
    return a + b;
}

function greet(name) {
    return name;
}

function getApiKey() {
    return process.env.API_KEY;
}

function processItems(items) {
    return items;
}

async function main() {
    const key = getApiKey();
    const total = add(key, key);
    const msg = greet(key);
    const items = processItems(key);
    console.log(total, msg, items);
}
