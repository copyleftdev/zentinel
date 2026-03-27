const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');

const SECRET_KEY = "hardcoded_secret_456";

function runCommand(cmd) {
    exec(cmd, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

function safeFunction(data) {
    const cleaned = data.trim();
    return cleaned.toUpperCase();
}

async function processFile(filepath) {
    const content = fs.readFileSync(filepath, 'utf8');
    eval(content);  // dangerous
    return content;
}

class UserManager {
    constructor(db) {
        this.db = db;
    }

    getUser(userId) {
        const query = `SELECT * FROM users WHERE id = ${userId}`;
        return this.db.query(query);  // SQL injection
    }

    deleteUser(userId) {
        exec(`rm -rf /tmp/${userId}`);  // command injection
    }
}

function main() {
    const app = express();
    const mgr = new UserManager(null);

    app.get('/user/:id', (req, res) => {
        const user = mgr.getUser(req.params.id);
        res.json(user);
    });

    runCommand("ls -la");
}

module.exports = { UserManager, runCommand };
