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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/8d9d02c02eabdf35e1f00b6407ed466e8599c48c/Screenshot%202026-09-08%20113751.png)

The screenshot above ^ gives us four matches:

editbooks.py — line 732

editbooks.py — line 874

helper.py — line 911, the function definition

web.py — line 345

The important discovery is that there are three callers, not just the web.py path we focused on during Lab 3.

**Inspect the first caller**

Start with the web.py caller because it appears to be the user-facing route we previously mapped

Run: Get-Content .\cps\web.py | Select-Object -Skip 320 -First 55

We're looking for the route above line 345 and specifically:

Route → HTTP method → authentication decorator → book_id → edit_book_read_status()

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/1c068156d98afc1ac3ee4ec52cdc0d90ab32ffa0/Screenshot%202026-09-08%20114756.png)

This confirms an important part of the read-status hypothesis.

The route is:

@web.route("/ajax/toggleread/<int:book_id>", methods=['POST'])
@user_login_required
def toggle_read(book_id):
    message = edit_book_read_status(book_id)

So this caller has:

POST request → authenticated user → user-controlled book_id → edit_book_read_status(book_id)

What we do not see in this route is a get_filtered_book() or equivalent book-visibility check before the helper is called.

That does not confirm a vulnerability yet, because the missing authorization check could exist elsewhere in the call chain.

Next, inspect the first editbooks.py caller

Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 700 -First 70

We want to compare whether that caller performs stronger object-level authorization before calling edit_book_read_status().



This editbooks.py caller is different from the web.py route.

Here, the helper is called with:

ret = helper.edit_book_read_status(book.id, vals['value'] == "True")

The important detail is that it uses book.id from an already-resolved book object, not the raw route book_id directly.

That suggests this path may already have stronger object authorization earlier in the function, because the code is operating on a book object that was likely fetched before reaching this block.

So right now we have:

web.py path: user-controlled book_id → helper directly

editbooks.py path: resolved book.id → helper

That makes the web.py path more interesting for our hypothesis.

Next: inspect how book is obtained in this editbooks.py function

Run:Get-Content .\cps\editbooks.py | Select-Object -Skip 630 -First 75

We want to see whether this function uses something like:

calibre_db.get_filtered_book(...)

before the read_status branch.



This output is still inside the middle of the same editing function, so we haven’t reached the part where the book object is originally loaded.

That matters because we need to know whether book was already filtered for the current user before line 732.

Run: Select-String -Path .\cps\editbooks.py -Pattern "get_filtered_book" | Select-Object LineNumber, Line

We’re looking for a get_filtered_book(...) call before line 732.

If we find one in the same function, that would show this editbooks.py path has an object-level visibility check before calling:

helper.edit_book_read_status(book.id, ...)

The get_filtered_book() calls are at lines 797, 1013, 1695, and 1931. Our first edit_book_read_status() call was around line 732.

So there is no get_filtered_book() call before line 732 shown by this search. That makes it more important to identify exactly how the book variable used at line 732 was obtained. It could be loaded through another function that still enforces access control.

**Find where book is loaded** 

Run:

We're looking for the beginning of that function and specifically something like:

Route

  ↓
  
Authentication/authorization decorators

  ↓
  
book_id

  ↓
  
Book lookup

  ↓
  
book variable

  ↓
  
edit_book_read_status(book.id)
