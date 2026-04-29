#!/usr/bin/env node
// Walks a markdown file, pulls every $...$ inline and $$...$$ display block,
// and parses each through KaTeX in strict mode.  Mirrors GitHub's renderer.
//
// Exit code 0 if every expression parses cleanly, 1 otherwise.  Writes one
// failure diagnostic per problem to stderr.
//
// Usage: node validate.js <report.md>
//
// Notes:
//   * GitHub uses KaTeX for $...$ and $$...$$ rendering, with `strict = false`
//     by default.  We deliberately turn strict ON so that things GitHub
//     "tolerates" but renders in surprising ways (\:, \;, \,, \!, mismatched
//     braces) become hard failures here.
//   * Block math ($$...$$) and inline math ($...$) are extracted with the
//     same rules GitHub uses: a $$ at the start of a line opens a display
//     block that must close with $$ on its own line; otherwise inline.

const fs = require('fs');
const path = require('path');

if (process.argv.length < 3) {
    console.error('usage: node validate.js <report.md>');
    process.exit(2);
}

const reportPath = process.argv[2];
const src = fs.readFileSync(reportPath, 'utf8');

// Resolve katex relative to this script so the validator works regardless
// of CWD.
const katex = require(path.join(__dirname, 'node_modules', 'katex'));

const problems = [];

// 1) Extract display math.  GitHub's display rule: $$...$$ where the opening
//    $$ is preceded by a newline (or BOF) and the closing $$ is followed by
//    a newline (or EOF).  We allow content to span multiple lines.
let stripped = src;
const displayRe = /(^|\n)\$\$([\s\S]*?)\$\$(?=\n|$)/g;
const displays = [];
stripped = stripped.replace(displayRe, (m, lead, body, off) => {
    displays.push({body, offset: off});
    // Replace by spaces of equal length so subsequent inline scan stays
    // line-aligned; preserve newlines so line numbers don't drift.
    return lead + m
        .slice(lead.length)
        .replace(/[^\n]/g, ' ');
});

// 2) Extract inline math from what's left.  GitHub's inline rule: $...$
//    where neither delimiter is preceded/followed by another $, and the
//    content does not contain a newline.  We also forbid digit-adjacent
//    closing $ ("$5 and $10" idiom) the same way GitHub does.
const inlineRe = /(?<![\$\\])\$(?!\s)([^\n$]+?)(?<!\s)\$(?![\d\$])/g;
const inlines = [];
let m;
while ((m = inlineRe.exec(stripped)) !== null) {
    inlines.push({body: m[1], offset: m.index});
}

function lineOf(offset) {
    return src.slice(0, offset).split('\n').length;
}

// User-style rules layered on top of KaTeX parsing.  These are valid LaTeX
// but the user has banned them in this report:
//   \;  \,  \!         — horizontal-spacing macros
//   \operatorname{...} — use built-in operators or \mathrm instead
// And we additionally flag:
//   <digit>e<+/-?digits> inside math — parses, but reads as variable e
//   raw `|` inside math in a markdown-table cell — corrupts the table
const STYLE_RULES = [
    {re: /\\[;,!](?![A-Za-z])/, msg: 'banned thin-space macro (\\; \\, \\!)'},
    {re: /\\operatorname\b/, msg: 'banned \\operatorname{...}; use \\mathrm or built-in operator'},
    {re: /\d\.?\d*e[+-]?\d/i, msg: 'scientific notation inside math; format as m \\times 10^{e} outside math'},
    {re: /\d{1,3}(?:,\d{3})+/, msg: 'comma-grouped integer inside math renders with ugly thin spaces; move the value outside the $...$ delimiters'},
];

function checkStyle(kind, body) {
    const out = [];
    for (const r of STYLE_RULES) {
        if (r.re.test(body)) out.push(r.msg);
    }
    return out;
}

function check(kind, body, offset, surrounding) {
    try {
        katex.__parse(body, {
            strict: 'error',
            throwOnError: true,
            displayMode: kind === 'display',
            macros: {},
        });
    } catch (e) {
        problems.push({
            kind,
            line: lineOf(offset),
            body: body.length > 80 ? body.slice(0, 77) + '...' : body,
            err: e.message.split('\n')[0],
        });
    }
    for (const msg of checkStyle(kind, body)) {
        problems.push({
            kind,
            line: lineOf(offset),
            body: body.length > 80 ? body.slice(0, 77) + '...' : body,
            err: msg,
        });
    }
    // Detect raw `|` inside inline math that sits in a markdown table row
    // (the row contains another `|`).
    if (kind === 'inline' && /\|/.test(body) && /\|/.test(surrounding)) {
        problems.push({
            kind,
            line: lineOf(offset),
            body: body.length > 80 ? body.slice(0, 77) + '...' : body,
            err: 'raw `|` inside inline math in a table row; use \\lvert / \\rvert / \\mid',
        });
    }
}

function lineText(offset) {
    const lineStart = src.lastIndexOf('\n', offset - 1) + 1;
    const lineEnd = src.indexOf('\n', offset);
    return src.slice(lineStart, lineEnd === -1 ? src.length : lineEnd);
}

for (const d of displays) check('display', d.body, d.offset, '');
for (const i of inlines) check('inline',  i.body, i.offset, lineText(i.offset));

console.log(`scanned ${displays.length} display + ${inlines.length} inline math expressions`);
if (problems.length === 0) {
    console.log('OK');
    process.exit(0);
}

console.error(`\n${problems.length} KaTeX strict-mode failure(s):\n`);
for (const p of problems) {
    console.error(`  ${reportPath}:${p.line}  [${p.kind}]`);
    console.error(`    body: ${p.body}`);
    console.error(`    err:  ${p.err}\n`);
}
process.exit(1);
