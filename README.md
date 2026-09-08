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

**Verify Static Analysis Tools**

First, return to your research-project root: cd C:\Users\eelve\Vulnerability-Research-Lab

Activate the virtual environment: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Then: .venv\Scripts\Activate.ps1

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/ce490799113e1816f075fc08e0a079e958c74b84/Screenshot%202026-09-08%20011002.png)

Your prompt should now start with: (.venv) PS C:\Users\eelve\Vulnerability-Research-Lab>

Now verify Semgrep: semgrep --version

Then verify CodeQL: codeql version

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/44992dcb79c6d19121648add5867fb57874c700e/Screenshot%202026-09-08%20011307.png)

**Trace Our First Hypothesis**

Go back into the target: cd .\targets\Calibre-Web-NextGen

![Image alt](![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/12aeb3459ebbf6ae7c33b123f8f454d974296fca/Screenshot%202026-09-08%20113656.png))

Now find everywhere edit_book_read_status() is called: Select-String -Path .\cps\*.py -Pattern "edit_book_read_status\(" | Select-Object Path, LineNumber, Line

We're trying to determine:

User request → Route → Authentication → book_id → edit_book_read_status() → authorization check → database change

The screenshot above ^ gives us four matches:

editbooks.py — line 732
editbooks.py — line 874
helper.py — line 911, the function definition
web.py — line 345

The important discovery is that there are three callers, not just the web.py path we focused on during Lab 3.

**Inspect the first caller**

