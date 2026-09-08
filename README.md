# Static-Analysis
Analyzed Calibre-Web NextGen source code using Semgrep, CodeQL, and manual review to identify potential security vulnerabilities.

**Establish the Static Analysis Baseline**

First, go into the Calibre-Web NextGen repository: cd C:\Users\eelve\Vulnerability-Research-Lab\targets\Calibre-Web-NextGen

Then verify the exact source baseline: 

git rev-parse HEAD

git branch --show-current

git status

And confirm the application version: Get-Content .\VERSION

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/dfeada499bfacbf1ba3576a804d247fcfa39802b/Screenshot%202026-09-08%20010019.png)

For our Lab 4 baseline, we expect:

Commit:
7e9221f455329bb3e6611b4652ac23b7f8629bb0

Branch:
main

Version:
4.1.43

Git status:
nothing to commit, working tree clean

Why we're doing this

Static-analysis results only mean something if we can tie them to a specific version and commit. If the code changes later, we’ll still know exactly which source tree produced our findings.

Take screenshots of the commands and outputs for your portfolio.

