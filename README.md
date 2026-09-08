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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/9a0fa5f55ab5fce6de5e1a0191668a58c6b4b52f/Screenshot%202026-09-08%20115144.png)

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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/1dea1c691012a74171d63a4ad5a95750d2515c59/Screenshot%202026-09-08%20115545.png)

This output is still inside the middle of the same editing function, so we haven’t reached the part where the book object is originally loaded.

That matters because we need to know whether book was already filtered for the current user before line 732.

Run: Select-String -Path .\cps\editbooks.py -Pattern "get_filtered_book" | Select-Object LineNumber, Line

We’re looking for a get_filtered_book(...) call before line 732.

If we find one in the same function, that would show this editbooks.py path has an object-level visibility check before calling:

helper.edit_book_read_status(book.id, ...)

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/53ec93e11ae23160764a9ada2bdcb34d639b1dce/Screenshot%202026-09-08%20115757.png)

The get_filtered_book() calls are at lines 797, 1013, 1695, and 1931. Our first edit_book_read_status() call was around line 732.

So there is no get_filtered_book() call before line 732 shown by this search. That makes it more important to identify exactly how the book variable used at line 732 was obtained. It could be loaded through another function that still enforces access control.

**Find where book is loaded** 

Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 540 -First 70

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



This gives us the missing context.

The editbooks.py path is protected by:

@login_required_if_no_ano

@edit_required

@metadata_db_write_lock()

def edit_book_param(param, vals):

and then loads the book with:

book = calibre_db.get_book(vals['pk'])

So this path has a stronger role boundary than the regular /ajax/toggleread/<book_id> route: the caller must have the edit role (or whatever edit_required permits). It does not use get_filtered_book() here, but that does not automatically indicate a flaw because this is a privileged metadata-editing workflow.

Our current comparison is:

Regular read-status route
POST /ajax/toggleread/<book_id> → @user_login_required → raw book_id → edit_book_read_status(book_id)

Privileged editor path
authenticated user → @edit_required → get_book(vals['pk']) → edit_book_read_status(book.id)

The regular-user path remains the more important hypothesis because it accepts a user-controlled book ID without an obvious visibility check in the route.

Inspect the second editbooks.py caller

Run: Get-Content .\cps\editbooks.py | Select-Object -Skip 840 -First 70

We’ll determine whether the second caller is another privileged editing path or whether it changes our read-status hypothesis



This confirms the second editbooks.py caller is also a privileged editing path.

The relevant route is:

@editbook.route("/ajax/readselectedbooks", methods=['POST'])

@user_login_required

@edit_required

def read_selected_books():

It then accepts multiple book IDs and calls:

helper.edit_book_read_status(book_id, markAsRead)

So far, our static trace looks like this:



The important point remains: the ordinary /ajax/toggleread/<book_id> route is the strongest candidate, because any authenticated user can reach the helper without an additional edit-role requirement being visible in the route.

We still do not have a confirmed vulnerability.

inspect the helper itself again

Now we need the complete function to determine exactly what happens to the supplied book_id.

Run: Get-Content .\cps\helper.py | Select-Object -Skip 900 -First 95

We're specifically looking for:

book_id → book lookup/visibility validation → current_user.id → database query/create/update → commit



This gives us enough evidence to make our first Lab 4 static-analysis assessment.

What the helper confirms

In the default configuration:

if not config.config_read_column:

the function searches only for:

ub.ReadBook.user_id == int(current_user.id)

ub.ReadBook.book_id == book_id

If no record exists, it creates one directly:

read_book = ub.ReadBook(
    user_id=current_user.id,
    book_id=book_id
)

We do not see get_filtered_book() or another book-visibility/access check before that database operation.

But look at the custom-column branch:

book = calibre_db.get_filtered_book(book_id, True)

So we have confirmed the inconsistency we identified in Lab 3:

Default read-status path: authenticated user + supplied book_id → user-bound state lookup/create → no explicit book-visibility check observed

Custom-column path: supplied book_id → get_filtered_book() → filtered book → update
