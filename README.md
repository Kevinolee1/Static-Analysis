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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/9db608f05260ad0b1c235fcdf5bb6bf684b8d146/Screenshot%202026-09-08%20121046.png)

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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/8360ada72ef96c23df55d8d65451e1daa65ef858/Screenshot%202026-09-08%20135023.png)

This confirms the second editbooks.py caller is also a privileged editing path.

The relevant route is:

@editbook.route("/ajax/readselectedbooks", methods=['POST'])

@user_login_required

@edit_required

def read_selected_books():

It then accepts multiple book IDs and calls:

helper.edit_book_read_status(book_id, markAsRead)

So far, our static trace looks like this:

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/67bcce35ce360c8ccbf408a94b1e7ef140d5e4da/Screenshot%202026-09-08%20135342.png)

The important point remains: the ordinary /ajax/toggleread/<book_id> route is the strongest candidate, because any authenticated user can reach the helper without an additional edit-role requirement being visible in the route.

We still do not have a confirmed vulnerability.

inspect the helper itself again

Now we need the complete function to determine exactly what happens to the supplied book_id.

Run: Get-Content .\cps\helper.py | Select-Object -Skip 900 -First 95

We're specifically looking for:

book_id → book lookup/visibility validation → current_user.id → database query/create/update → commit

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/3b51374fa3a60c6b0d737fd1f2daba964f89e0d5/Screenshot%202026-09-08%20135552.png)

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

**finding status**

Static-analysis candidate: SURVIVES 

This does not mean we have discovered an IDOR/BOLA.

What we've established is narrower and defensible:

The default read-status path accepts a user-controlled book ID and can create or modify user-specific ReadBook and KoboReadingState records without an explicit book-visibility check observed in the traced path. The alternate custom-column implementation does perform a filtered book lookup.

That's a good vulnerability-research lead.

Next — check whether another layer invalidates our hypothesis

Before carrying this into dynamic testing, we need to examine ReadBook and its database relationships. A foreign-key constraint or model behavior could prevent nonexistent/unauthorized book IDs from producing a meaningful security impact.

Run: Select-String -Path .\cps\ub.py -Pattern "class ReadBook" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/0094d10bc105ce43f9183861082a21c3d73b72de/Screenshot%202026-09-08%20140712.png)

The screenshot above ^ confirms:

Line 713: class ReadBook(Base):

Now we need to inspect the model and determine what database constraints exist on book_id.

Inspect ReadBook

Run: Get-Content .\cps\ub.py | Select-Object -Skip 705 -First 75

We're specifically looking for:

ReadBook

   ↓
   
user_id

   ↓
   
book_id

   ↓
   
ForeignKey?

   ↓
   
Unique constraint?

   ↓
   
Relationships / validation

This matters because we want to determine whether the database itself prevents the suspicious read-status path from operating on an inappropriate book_id.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/bae456bd8c7e831fb056a12954b0127590f3ab52/Screenshot%202026-09-08%20141105.png)

This is an important result. The database model does not eliminate our hypothesis.

In ReadBook, the fields are:

book_id = Column(Integer, unique=False)

user_id = Column(Integer, ForeignKey('user.id'), unique=False)

The critical detail is that book_id is not a foreign key. The database enforces that user_id references a real user, but it does not enforce that book_id references a valid or visible book.

The model does enforce:

UniqueConstraint(
    'user_id',
    
    'book_id',
    
    name='uq_book_read_link_user_book'
)

That prevents duplicate read-status rows for the same user/book pair, but it does not provide object-level authorization.

Current static-analysis assessment

Our read-status candidate becomes stronger:

Authenticated request → user-controlled book_id → no explicit visibility check → ReadBook lookup/create → no database FK on book_id

So this possible false-positive explanation has now been eliminated:

“Maybe the database rejects unauthorized or invalid book IDs automatically.”

It does not appear to.

We still should not call this an IDOR/BOLA vulnerability yet. We haven't proven security impact or actual runtime behavior with a book the user cannot access.

Inspect KoboReadingState

The same helper also creates:

ub.KoboReadingState(

    user_id=current_user.id,
    
    book_id=book_id
)

Let's see whether that model adds any additional constraint.

Run: Select-String -Path .\cps\ub.py -Pattern "class KoboReadingState" | Select-Object LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/52fad61f1d1cd0396bb76f5a1031633d44fc52c4/Screenshot%202026-09-08%20141510.png)

We found the model at:

Line 1188: class KoboReadingState(Base):

Now let's inspect the class and see whether book_id has a foreign-key or other constraint that could stop the operation.

Run: Get-Content .\cps\ub.py | Select-Object -Skip 1180 -First 85

We're looking specifically for:

book_id → ForeignKey? → user_id → uniqueness constraints → relationships



This confirms the same pattern in KoboReadingState.

The model has:

user_id = Column(Integer, ForeignKey('user.id'))

book_id = Column(Integer)

and only enforces uniqueness with:

UniqueConstraint('user_id', 'book_id', name='uq_kobo_reading_state_user_book')

So again, book_id is not protected by a database foreign key or visibility rule.

Read-status static-analysis conclusion

At this point, the Lab 3 hypothesis survives static analysis:

Authenticated user
→ supplies book_id

→ /ajax/toggleread/<book_id>

→ edit_book_read_status(book_id)

→ no explicit get_filtered_book() in the default branch

→ ReadBook / KoboReadingState rows can be created for that book_id

→ database does not independently validate that the book is visible or even represented by a foreign key.

That is enough to classify this as a:

Static-analysis candidate: VALID FOR LATER DYNAMIC TESTING 

Still not a confirmed vulnerability, because we have not yet demonstrated that a user can affect or learn anything about a book they should not access.

Move to the archive-status hypothesis

Run:Select-String -Path .\cps\*.py -Pattern "change_archived_books\(" | Select-Object Path, LineNumber, Line



The most important one to start with is web.py line 355, because we already saw that it is reachable by an ordinary authenticated user:

@web.route("/ajax/togglearchived/<int:book_id>", methods=['POST'])

@user_login_required

def toggle_archived(book_id):

    change_archived_books(book_id, ...)

Just like our read-status candidate, the route itself didn't show an object-visibility check.

Inspect the archive helper

Now run:Get-Content .\cps\kobo_sync_status.py | Select-Object -Skip 460 -First 75

We're looking for the complete:

book_id

   ↓
   
change_archived_books()

   ↓
   
current_user.id

   ↓
   
Book visibility check?

   ↓
   
ArchivedBook lookup/create

   ↓
   
Database write

This will tell us whether the archive-status hypothesis survives deeper static analysis the way the read-status hypothesis did.



This confirms that our archive-status hypothesis also survives this part of static analysis. 

The important section is:

archived_book = s.query(ub.ArchivedBook).filter(

    and_(
    
        ub.ArchivedBook.user_id == int(current_user.id),
        
        ub.ArchivedBook.book_id == book_id
    )
).first()

If no record exists, the application creates one directly:

archived_book = ub.ArchivedBook(

    user_id=current_user.id,
    
    book_id=book_id
)

There is no explicit get_filtered_book() or equivalent book-visibility check inside this helper.

So the path we've traced is:

Authenticated user → user-controlled book_id → change_archived_books() → current-user binding → no explicit book visibility check → ArchivedBook lookup/create → database commit

Again, binding the row to current_user.id prevents directly modifying another user's archive row, but that's different from checking whether the current user is authorized to reference the supplied book.

inspect the ArchivedBook database model

Just as we did with ReadBook, we need to determine whether the database itself constrains book_id.

If book_id also lacks an appropriate constraint, we'll continue false-positive elimination before deciding whether this candidate advances to later dynamic validation.

Run: Select-String -Path .\cps\ub.py -Pattern "class ArchivedBook" | Select-Object LineNumber, Line

The above ^ screenshot confirms:

Line 796: class ArchivedBook(Base):

Now we need to inspect that model to see whether book_id has a database constraint.

Continue the archive-status analysis

Run: Get-Content .\cps\ub.py | Select-Object -Skip 790 -First 55

We're specifically looking for:

ArchivedBook

   ↓
   
user_id → ForeignKey?

   ↓
   
book_id → ForeignKey?

   ↓
   
Unique constraint?

   ↓
   
is_archived

The key question is whether the database independently requires book_id to correspond to a valid book



This confirms the archive-status hypothesis survives static analysis too. 

The model shows:

user_id = Column(Integer, ForeignKey('user.id'))

book_id = Column(Integer)

and:

UniqueConstraint(

    'user_id',
    
    'book_id',
    
    name='uq_archived_book_user_book'
)

So the database ensures the user exists and prevents duplicate (user_id, book_id) rows, but book_id is not a foreign key and there is no object-visibility enforcement at the model layer.

That gives us this static path:

Authenticated user → user-controlled book_id → change_archived_books() → current-user binding → no explicit visibility check → ArchivedBook row creation/update → database commit

Archive-status static-analysis conclusion

Static-analysis candidate: VALID FOR LATER DYNAMIC TESTING 

This is still not a confirmed IDOR/BOLA. What we have proven is that the helper and model do not visibly enforce book-level authorization. We still need runtime testing later to determine whether a user can actually affect state for a book they should not be able to access.

At this point, both of our object-authorization hypotheses have survived static review:

Read-status candidate 

Archive-status candidate 

Next, we should move to the OAuth/OIDC account-matching hypothesis and trace how username, email, sub, and provider identity are used when mapping an external identity to a local account.
