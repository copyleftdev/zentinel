import * as fs from 'fs'

// Missing closing brace and semicolons
function brokenFunc(x: string {
    const result = x.trim(
    return result

interface BrokenInterface {
    name: string
    // missing closing brace

class BrokenClass {
    constructor(public name: string {
        this.name = name

    getVal(): string
        return this.name
