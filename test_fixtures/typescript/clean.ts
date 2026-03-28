import * as fs from 'fs';
import * as crypto from 'crypto';
import { exec } from 'child_process';

const SECRET_KEY: string = "hardcoded_secret_456";

function runCommand(cmd: string): void {
    exec(cmd, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

function safeFunction(data: string): string {
    const cleaned = data.trim();
    return cleaned.toUpperCase();
}

async function processFile(filepath: string): Promise<string> {
    const content = fs.readFileSync(filepath, 'utf8');
    return content;
}

interface User {
    id: number;
    name: string;
}

class UserManager {
    private db: any;

    constructor(db: any) {
        this.db = db;
    }

    getUser(userId: number): User {
        const query = `SELECT * FROM users WHERE id = ${userId}`;
        return this.db.query(query);
    }

    deleteUser(userId: number): void {
        exec(`rm -rf /tmp/${userId}`);
    }
}

function main(): void {
    const mgr = new UserManager(null);
    runCommand("ls -la");
    const user = mgr.getUser(42);
    console.log(user);
}
