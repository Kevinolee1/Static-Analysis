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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/63df89b5846c9d04a922c391ec1753b01906a860/Screenshot%202026-09-08%20141722.png)

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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/7433e1e110650e5454c6191cfde7c49e9fa9d12d/Screenshot%202026-09-08%20142020.png)

We found five locations involving change_archived_books

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/0f772abdbd0b1a56640b13390c8888ce0cf1c03e/Screenshot%202026-09-08%20143102.png)

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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/f6576470d4abfc581fb81b8d17d961fe0e50ae3e/Screenshot%202026-09-08%20143344.png)


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

![Image alt](![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/a0754b115195e87c814cc8f51a6e3fb685e4170e/Screenshot%202026-09-08%20143707.png))

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

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/f2ca92a3f896d7e2cb9479adbb278ed435e5894e/Screenshot%202026-09-08%20143905.png)

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

**Static Analysis Target: OAuth/OIDC**

Our question is:

Can an external OIDC identity become associated with an existing local account based on username/email matching before the provider sub is fully bound?

We are still doing source review only.

Start by locating the main registration/mapping function: Select-String -Path .\cps\oauth_bb.py -Pattern "def register_user_from_generic_oauth" | Select-Object LineNumber, Line

Then inspect the function: Get-Content .\cps\oauth_bb.py | Select-Object -Skip 320 -First 190

We’re looking for this flow:

OIDC userinfo

   ↓
   
username / email / sub

   ↓
   
existing local user lookup

   ↓
   
group checks

   ↓
   
account creation or account match

   ↓
   
provider + sub binding


![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/f29a1127184b7ca7d7945c21d091e57d9ce8bffa/Screenshot%202026-09-09%20083039.png)

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/02e6ca82dfcafb008a6378eac947487664e3f5e7/Screenshot%202026-09-09%20083101.png)

This output gives us the key part of the OAuth/OIDC path. The hypothesis still deserves investigation, but we need the remainder of the function before making the final static-analysis decision.

The important sequence is:

OIDC userinfo

     ↓
     
preferred_username

email

sub

     ↓
     
Require username + sub

     ↓
     
Search existing local account by username

     ↓
     
If none, search by email

     ↓
     
Group authorization

     ↓
     
Existing account OR create new account

     ↓
     
OAuth identity binding

The code explicitly requires both provider_username and provider_user_id (sub).

But for a normal login, it then attempts to locate an existing local account first by:

ub.User.name == provider_username

and, if that fails, by:

ub.User.email == provider_email

before the portion we've seen establishes how the provider identity is bound.

That's the exact behavior our Lab 3 hypothesis predicted.

There are also meaningful controls: required-group authorization happens before account creation/login, and administrator assignment is gated by both the IdP group and the application's group-management configuration.

We need the rest of the function

Your pasted output ends around the existing-user role-management logic. Before deciding whether account matching presents a real candidate, we need to see how provider_user_id (sub) is subsequently associated with the local user.

Run: Get-Content .\cps\oauth_bb.py | Select-Object -Skip 500 -First 120

We're specifically looking for:

existing local user → existing OAuth binding lookup → provider → sub → binding creation/update → login

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/ce8906630a50adf906036fe8bb86b95039ce2358/Screenshot%202026-09-09%20083814.png)

This strengthens the OAuth/OIDC hypothesis.

The key sequence is now clear:

OIDC username/email/sub

        ↓
        
Existing local user matched by username

        ↓
        
Fallback match by email

        ↓
        
OAuth lookup by provider + sub

        ↓
        
If no OAuth entry exists, create one

        ↓
        
oauth.user = matched local user
        ↓
        
      Commit

        ↓
        
Login through bind_oauth_or_register()

The important line is:

oauth.user = user

Because user may have been selected earlier solely by matching the external provider_username or provider_email. The OAuth record itself is correctly keyed by both provider and sub, but that happens after the local-account match.

So our static-analysis question becomes very specific:

Can a new external identity with a matching username or email cause its provider sub to become permanently bound to an existing local account without an additional ownership-verification step?

That is a meaningful authentication candidate, but it is still not a confirmed account-takeover vulnerability. Whether it's exploitable depends on assumptions such as how the IdP guarantees usernames/emails, whether email is verified, and whether the application intentionally supports automatic account linking

**Inspect the final login function**

Run: Select-String -Path .\cps\oauth_bb.py -Pattern "def bind_oauth_or_register" | Select-Object LineNumber, Line

Then send me the line number.

We’ll inspect that function next to verify whether it logs in strictly through the newly created provider + sub binding or performs another ownership check.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/82feff64c79ff346994723b9bdc544ff26d48a6e/Screenshot%202026-09-09%20084244.png)

The function begins at:

Line 631: def bind_oauth_or_register(provider_id, provider_user_id, redirect_url, provider_name):

This is the final piece we need to trace for the OAuth/OIDC hypothesis.

Run: Get-Content .\cps\oauth_bb.py | Select-Object -Skip 625 -First 90

We're looking for:

provider + sub

     ↓
     
OAuth record lookup

     ↓
     
Associated local user

     ↓
     
Any additional identity/ownership check?

     ↓
     
login_user()

If this function simply retrieves the OAuth record we just created and authenticates its associated local user, that would further strengthen the static-analysis candidate.

We still won't classify this as an account-takeover vulnerability until the complete authentication chain and intended account-linking behavior are established.


![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/51a56022c8763b26f975d11efe6f1f85c6f26c8b/Screenshot%202026-09-09%20084629.png)

This completes the key OAuth/OIDC call chain, and the OAuth account-matching hypothesis survives static analysis. 

The login function looks up the OAuth record using:

provider=provider_id
provider_user_id=provider_user_id

and then, if that record is associated with a user, it directly authenticates that local account:

if oauth_entry and oauth_entry.user:
    login_user(oauth_entry.user)

There is an important protection against linking the same OAuth identity to a different already-authenticated user, but that check occurs after the OAuth record already has an associated local user.

So the static flow we have now traced is:

OIDC userinfo

   ↓
   
username + email + sub

   ↓
   
Existing local user matched by username
or fallback to email

   ↓
   
OAuth record looked up/created using provider + sub

   ↓
   
oauth.user = matched local user

   ↓
   
Commit

   ↓
   
bind_oauth_or_register()

   ↓
   
OAuth record found by provider + sub

   ↓
   
login_user(oauth_entry.user)
OAuth/OIDC static-analysis conclusion

Static-analysis candidate: VALID FOR LATER DYNAMIC TESTING 

The specific question for later validation is:

Can a newly authenticated external OIDC identity become bound to an existing local account solely because its provider username or email matches that local account, without an additional ownership-verification step?

We still should not call this account takeover. Exploitability depends on the IdP's guarantees around usernames, email verification, uniqueness, and the application's intended automatic account-linking behavior.

So far, Lab 4 has three surviving candidates:

Read-status object authorization 

Archive-status object authorization 

OAuth/OIDC account matching 

Next, we should move to the LDAP local-password fallback hypothesis.


Now we’ll trace the LDAP local-password fallback hypothesis.

Our question is:

If LDAP explicitly rejects a user’s credentials, can Calibre-Web NextGen still authenticate that same account using its stored local password?

We are still doing static analysis only.

Run this first: Select-String -Path .\cps\web.py -Pattern "login_result is False|login_result is None|check_password_hash" | Select-Object LineNumber, Line

Then inspect the surrounding LDAP login logic: Get-Content .\cps\web.py | Select-Object -Skip 3020 -First 105

We’re looking for this decision flow:

Username + Password

      ↓
      
LDAP bind_user()

      ↓
      
LDAP result

  ┌────┼────┐
  
 True None False
 
  ↓     ↓     ↓
  
Login  fallback?  local-password fallback?

We’ll confirm whether the False branch really allows local-password authentication before deciding whether this LDAP hypothesis survives Lab 4 static analysis.

the LDAP hypothesis survives static analysis. 

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/fd992a0efd7adbe6df94d4dd5acfb178140f9c84/Screenshot%202026-09-09%20092038.png)

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/104aea72f627d27637df0d692eebb5dc52aab075/Screenshot%202026-09-09%20092339.png)

Your output confirms two different fallback behaviors:

elif login_result is None ...

means LDAP unavailable / indeterminate and the app may use the stored local password.

But this branch is more security-relevant:

elif login_result is False and user and user.password \

        and check_password_hash(str(user.password), form['password']) \
        
        and user.name != "Guest":

That means LDAP explicitly rejected the credentials, yet the application can still authenticate the local account using its stored password.

The flow is:

Username + password → LDAP bind → LDAP returns False → local user exists → local password hash matches → handle_login_user()

That is different from a normal availability fallback.

Lab 4 LDAP conclusion

Static-analysis candidate: VALID FOR LATER DYNAMIC TESTING 

The precise question for later validation is:

If an administrator expects LDAP to be authoritative and disables or revokes a user in LDAP, can that user still authenticate with a pre-existing local password?

We still should not call this an authentication bypass yet because it may be intentional product behavior or documented fallback semantics.

At this point, all four Lab 3 hypotheses have survived targeted static review:

Read-status object authorization 

Archive-status object authorization 

OAuth/OIDC account matching 

LDAP local-password fallback 

The next logical part of Lab 4 is to begin Semgrep analysis and see whether it surfaces any additional security-sensitive patterns beyond these four manually traced candidates.

**Semgrep Analysis**

Return to the project root

From the target repo, run: cd C:\Users\eelve\Vulnerability-Research-Lab

Make sure the virtual environment is still active:

(.venv) PS C:\Users\eelve\Vulnerability-Research-Lab>

un the first Semgrep scan

Run this against the local cps source directory: semgrep scan --config auto .\targets\Calibre-Web-NextGen\cps

This will scan the local Python application using Semgrep’s automatically selected rule set.

We are looking for categories such as:

Authentication

Authorization

Unsafe input handling

Path/file handling

Injection patterns

Dangerous subprocess usage

Cryptographic misuse

Potential XSS

SQL-related issues

A Semgrep alert is only a potential finding. We will manually inspect anything interesting before it becomes a Lab 4 candidate.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/0642487d33c668b0e4492c97024dd53ac25b4650/Screenshot%202026-09-09%20095950.png)

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/5bf29163088b2334d24e4880225ef4fcf1d8bb37/Screenshot%202026-09-09%20101129.png)

The Semgrep scan completed successfully. It scanned 884 Git-tracked files with 459 rules and produced 141 findings. There were also several rule timeouts, so this was not perfect coverage.

The important part now is triage. We are not calling these 141 vulnerabilities.

One result is immediately worth investigating because it intersects with the remote-login trust boundary we already mapped:

cps\api\auth.py

flask-url-for-external-true

verify_url = url_for(

    "remotelogin.verify_token",
    
    token=auth_token.auth_token,
    
    _external=True
    
)

Semgrep warns that _external=True can cause Flask to construct an absolute URL using request host information, potentially creating a Host-header injection condition.

That does not mean Calibre-Web NextGen is vulnerable. We need to determine where that URL goes, whether the host is trusted/configured, and whether an attacker-controlled Host value could influence a security-sensitive remote-login link.

Semgrep Investigation 1 — Remote Login URL Generation

Run this from your project root: Select-String -Path .\targets\Calibre-Web-NextGen\cps\api\auth.py -Pattern "_external=True" -Context 15,15

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/584fb4171e4333819c2be6d938b26cd37aec0220/Screenshot%202026-09-09%20101610.png)

This gives us the surrounding code so we can answer:

Request input → Host handling → url_for() → verification URL → security impact?

We also have other findings to triage later, including Semgrep's SHA-1 warning and make_response() XSS warnings. For example, it flagged make_response(text_data), but that requires tracing where text_data originates before deciding whether XSS is possible.

this finding is worth tracing further, but it is still only a candidate.

What your output confirms is:

Unauthenticated SPA request

   ↓
   
RemoteAuthToken created

   ↓
   
url_for(..., _external=True)

   ↓
   
verify_url returned in JSON

   ↓
   
same URL embedded into QR code

The security-relevant point is that the absolute verify_url is generated server-side and then sent back to the client as both a URL and QR-code destination. If the application trusts an attacker-controlled Host header here, that could potentially cause the QR code or returned link to point to an attacker-controlled domain while still containing the real token.

We still need to prove two things before this becomes a real vulnerability: whether Flask’s host generation is constrained by configuration/proxy handling, and whether the token in that generated URL is security-sensitive enough for host manipulation to matter.

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\*.py -Pattern "ProxyFix|TRUSTED_HOSTS|SERVER_NAME|host_url|request.host|X-Forwarded-Host" | Select-Object Path, LineNumber, Line

We’re specifically checking whether the application has a trusted-host or proxy configuration that neutralizes the Semgrep warning. If it does, this may be a false positive. If it does not, this candidate gets more interesting.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/1b5bdacd263642ea26e819459d4de44d941f75de/Screenshot%202026-09-09%20103355.png)

This output shows the application does use ProxyFix, including support for X-Forwarded-Host, so the Semgrep result cannot be dismissed yet.

The key question now is how many proxy hops are trusted by default. If x_host is greater than 0, Flask may replace the request host using X-Forwarded-Host. If that header can be supplied directly by an untrusted client in a deployment, _external=True could generate a poisoned verification URL.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\__init__.py | Select-Object -Skip 95 -First 30

We want to inspect this section:

PROXYFIX_X_FOR

PROXYFIX_X_PROTO

PROXYFIX_X_HOST

proxyfix_hops

ProxyFix(...)

Right now, the status is:

Semgrep Host Header candidate — still under investigation 🟡

We have confirmed the app generates a security-sensitive remote-login URL using _external=True, and we have confirmed ProxyFix can affect host handling. We have not yet proven attacker control over the generated host.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/1f7c4864290081e061ebc18e54b3250ee935aab1/Screenshot%202026-09-09%20102311.png)

**static-analysis step**

Search the repository documentation for the proxy configuration: Get-ChildItem .\targets\Calibre-Web-NextGen -Recurse -File -Include *.md,*.txt,*.yml,*.yaml | Select-String -Pattern "TRUSTED_PROXY_COUNT|PROXYFIX_X_HOST|X-Forwarded-Host" | Select-Object Path, LineNumber, Line

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/d294181d4bd90b333b39c43c44184e21e19cd4a6/Screenshot%202026-09-09%20103355.png)

That changes the assessment in an important way: the proxy behavior is documented, including TRUSTED_PROXY_COUNT and separate PROXYFIX_X_HOST configuration. So we should not frame this as an obvious unsafe default without reading that documentation context first.

The best next step is to inspect the README section around those lines, especially 521–534 and the later proxy guidance.

Run: Get-Content .\targets\Calibre-Web-NextGen\README.md | Select-Object -Skip 515 -First 30

Then also: Get-Content .\targets\Calibre-Web-NextGen\README.md | Select-Object -Skip 640 -First 65

What we’re checking now is whether the maintainers explicitly warn users that forwarded-host trust must match the real proxy chain and that untrusted clients must not be allowed to supply those headers.

Current status

Semgrep Host Header candidate: NEEDS DOCUMENTATION REVIEW 🟡

The candidate is still technically interesting, but the presence of explicit deployment guidance makes it more likely this could be a deployment-hardening issue or false positive rather than a product vulnerability.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/0c02256a5558e36cd7f2972a25308a3c939e2199/Screenshot%202026-09-09%20103903.png)

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/a67f47cf801c4a220088430e51bd302c5639bce6/Screenshot%202026-09-09%20103949.png)

This documentation materially lowers the likelihood that the Semgrep result is a product vulnerability.

The README explicitly says to “Count only proxies you control and that overwrite or sanitize the corresponding header.” That is exactly the security assumption ProxyFix depends on. It also documents that PROXYFIX_X_HOST can be tuned independently. Based on that, the maintainers are clearly treating forwarded-host trust as a deployment responsibility rather than blindly trusting arbitrary client headers.

Semgrep Finding 1 — Conclusion

Host Header Injection via _external=True

Status: likely false positive / configuration-dependent

Do not promote to vulnerability candidate yet.

What we have established is:

_external=True

→ absolute verification URL

→ ProxyFix can influence host

→ x_host defaults to 1

→ documentation explicitly requires trusted/sanitized proxies

So the risky condition would mainly arise from misconfiguration, such as exposing the app directly while still trusting forwarded headers or using a proxy that does not sanitize them. That is not enough by itself to claim a product flaw.

Semgrep flagged external URL generation in the remote-login API as a potential Host-header injection risk. Manual review confirmed that the application uses ProxyFix with configurable forwarded-host trust. Project documentation explicitly instructs administrators to trust only controlled proxies that overwrite or sanitize forwarded headers. The finding is therefore currently classified as configuration-dependent and not a confirmed vulnerability.

**Semgrep finding**

The next one I recommend we inspect is the open redirect finding in:

cps\search.py

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\search.py | Select-Object -First 90

We’ll trace whether user-controlled request.args can actually reach redirect() without same-origin validation.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/c09586e26730b791ef1d7d49289576bd980448d5/Screenshot%202026-09-09%20104605.png)

This specific cps\search.py open-redirect finding looks like a false positive.

The user controls:

term = request.args.get("query")

but that value is only inserted as the query parameter inside:

url_for(

    'web.books_list',
    
    data="search",
    
    sort_param='stored',
    
    query=term.strip()
)

The redirect destination itself is a known internal Flask endpoint:

web.books_list

So the flow is:

User-controlled search term

        ↓
        
URL query parameter

        ↓
        
url_for("web.books_list", ...)

        ↓
        
Internal application URL

        ↓
        
    redirect()

An input such as:

https://evil.example

would become data inside the internal search URL rather than replacing the redirect destination.

Semgrep Finding 2 — Conclusion

Potential open redirect in search.py

Status: False Positive 

Semgrep flagged the search route as a potential open redirect because request-controlled data reaches redirect(). Manual source review showed that the destination is generated through Flask url_for() using a fixed internal endpoint. The user-controlled search term is passed only as a query parameter and does not control the redirect host or destination. The finding was therefore classified as a false positive.

Next finding — more interesting

Semgrep also found multiple redirects based directly on:

request.environ["HTTP_REFERER"]

inside cps\shelf.py.

That is more worthy of review because Referer is request-controlled metadata and may contain an external URL.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\shelf.py | Select-Object -Skip 330 -First 105

We’ll check whether those redirects pass through a same-origin validation helper before we decide whether this is another false positive or a real candidate.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/ad383a3fc98ee08da544af26d4c2c63424fe4317/Screenshot%202026-09-09%20105135.png)

This one is more interesting than the search.py result.

The route directly redirects to the raw HTTP_REFERER value in several places:

return redirect(request.environ["HTTP_REFERER"])

and also:

return redirect(request.environ.get("HTTP_REFERER") or url_for('web.index'))

The important difference is that this value is not being wrapped in url_for() or obviously passed through a same-origin validation helper in the code you showed.

So the static flow is:

Client-supplied Referer header

        ↓
        
request.environ["HTTP_REFERER"]

        ↓
        
redirect(...)

        ↓
        
Potential external destination

Semgrep Finding 3 — Current status

Potential open redirect via HTTP_REFERER

Status: Valid static candidate for local dynamic testing 🟠

We still need to check whether Flask/Werkzeug normalizes this or whether another wrapper prevents external redirects. But from the source shown, I do not see a local validation check in these branches.

There is another important point: the route is protected with:

@user_login_required

So any practical impact would likely require an authenticated user and a request that reaches one of these redirect branches. That affects severity but not whether the redirect behavior exists.

**Check for an existing redirect-safety helper**

You already have a cps\redirect.py file that looked like it contains host comparison logic. Before promoting this candidate, we should see whether shelf.py imports or uses that helper anywhere.

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\shelf.py -Pattern "redirect.py|is_safe|safe_redirect|redirect_back|redirect\(" | Select-Object LineNumber, Line

If there is no safety helper around these HTTP_REFERER redirects, this finding will stay on our shortlist for

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/35d07b57522129232f4fdf7c280ad9ccc07d9719/Screenshot%202026-09-09%20122535.png)

This confirms something important: in shelf.py, the HTTP_REFERER redirects shown are direct calls to redirect(). Your search did not reveal an is_safe, safe_redirect, or similar validation helper around them.

There are several occurrences, including lines 188, 359, 375, 394, 405, 412, 487, 573, and 586.

Semgrep Finding 3 — Static conclusion

Potential open redirect through HTTP_REFERER

Status: VALID FOR LATER DYNAMIC TESTING 🟠

Our current trace is:

Authenticated request

        ↓
        
Client-controlled Referer header

        ↓
        
request.environ["HTTP_REFERER"]

        ↓
        
No visible same-origin validation

        ↓
        
Flask redirect()

        ↓
        
Potential external URL

That is stronger than the search.py false positive. But we still do not call it a confirmed open-redirect vulnerability until we reproduce it in the authorized local instance and determine practical impact.

For your Lab 4 notes:

Semgrep identified multiple redirects in shelf.py that use the HTTP Referer header as the redirect destination. Manual source review found no visible same-origin or safe-redirect validation around these calls. Because the route requires authentication and some redirects depend on specific application states, the finding remains a static-analysis candidate pending controlled local validation.

Next Semgrep finding

Before dynamic testing, let's continue triaging the Semgrep results.

We saw an XSS warning involving:

return make_response(text_data)

Let's trace that next.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\web.py | Select-Object -Skip 2580 -First 70

We're going to determine exactly where text_data comes from and what content type is returned before deciding whether Semgrep found an actual XSS candidate.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/152d65ac76f8a0b4b616dc2f316efa19573d4015/Screenshot%202026-09-09%20122718.png)

This gives us enough to classify the Semgrep XSS warning more precisely.

Semgrep Finding 4 — make_response(text_data)

The important path is:

Authenticated/authorized viewer

        ↓
        
Requests a TXT book

        ↓
        
Application reads the TXT file

        ↓
        
Detects/decodes its encoding

        ↓
        
    text_data

        ↓
        
make_response(text_data)

The concern is that unlike the later general file-serving response, this TXT branch does not visibly set:

Content-Type

X-Content-Type-Options: nosniff

Content-Security-Policy

Content-Disposition

Meanwhile, immediately afterward the general response explicitly adds:

response.headers['Content-Disposition'] = 'inline'

response.headers['X-Content-Type-Options'] = 'nosniff'

response.headers['Content-Security-Policy'] = "script-src 'none'; object-src 'none'"

That difference is worth investigating.

However, we cannot call this XSS yet. make_response() may assign a safe MIME type based on the response data, and we also need to determine whether potentially attacker-controlled TXT content can reach this branch.

Current classification

Potential stored/content-sniffing XSS through TXT book serving

Status: STATIC CANDIDATE 🟠 — needs more source tracing

The next question is whether TXT uploads are permitted and how their MIME/extension validation works.

Run this: Select-String -Path .\targets\Calibre-Web-NextGen\cps\*.py -Pattern "TXT|txt|ALLOWED_EXTENSIONS|allowed_file|allowed_extension" | Select-Object Path, LineNumber, Line

Then we'll determine whether a user can introduce a crafted .txt file into the library and whether this candidate deserves Lab 5 dynamic testing.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/cb0bcc82724657b08901c8433754058e9d4b43bf/Screenshot%202026-09-09%20123159.png)

this strengthens the TXT candidate enough to keep investigating.

Your search confirms that TXT is explicitly included in EXTENSIONS_UPLOAD in constants.py, and the upload paths in editbooks.py perform extension/MIME validation. So TXT content can legitimately enter the application through its upload functionality, subject to permissions and configuration.

We now need to inspect exactly what the MIME validation does. That will tell us whether it validates only that the file is a legitimate text file or provides some protection against HTML/script content.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\file_helper.py | Select-Object -Skip 45 -First 45

Current Finding 4 status: 🟠 Static candidate

We have not demonstrated XSS. So far we've established:

TXT is an allowed upload format

        ↓
        
Upload code performs MIME/extension validation

        ↓
        
TXT can later reach serve_book()

        ↓
        
TXT bytes become text_data

        ↓
        
make_response(text_data)

        ↓
        
No explicit security headers visible in this branch

        ↓
        
Need to inspect MIME validation + resulting HTTP response

If the validation still permits ordinary TXT containing HTML-like markup—which may be perfectly valid for a text file—the decisive question will eventually be what Content-Type and browser protections the TXT response actually receives in our local lab.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/8fa209cf2b41df8688763ef63c90760e12dc8d95/Screenshot%202026-09-09%20123435.png)

This tells us the upload validation is primarily checking whether the detected MIME type matches one of the permitted formats. It does not sanitize the contents of a TXT file.

That alone isn't a vulnerability—TXT files are expected to contain arbitrary text. The security question is how that content is served to the browser.

Finding 4 — What we've established

Uploaded file

   ↓
   
Extension must be allowed

   ↓
   
libmagic detects MIME type

   ↓
   
MIME must match an allowed type

   ↓
   
TXT stored in library

   ↓
   
serve_book() reads raw TXT

   ↓
   
text_data

   ↓
   
make_response(text_data)

   ↓
   
No explicit Content-Type / nosniff / CSP in this branch

So Finding 4 remains 🟠 Static Candidate. We still should not label it XSS.

There's one more static check I want before saving this for Lab 5: determine whether the application sets security headers globally. A global after_request handler or middleware could completely change our conclusion.

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\*.py -Pattern "after_request|X-Content-Type-Options|Content-Security-Policy|nosniff" | Select-Object Path, LineNumber, Line

If global response handling already adds nosniff or a restrictive CSP, this Semgrep finding may drop substantially in priority. If it doesn't, we'll keep the TXT-serving path for controlled Lab 5 testing.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/22f17fc4c03f0c11fadcecfd16349934eebf1c9f/Screenshot%202026-09-09%20123808.png)

This changes Finding 4 significantly.

Your output shows an app-wide after_request hook in web.py, and lines 175–176 appear to apply:

resp.headers['Content-Security-Policy'] = csp

resp.headers['X-Content-Type-Options'] = 'nosniff'

That means the security headers we thought were missing from the TXT-specific branch may actually be applied globally before the response reaches the browser.

Finding 4 — likely false positive

Potential XSS through make_response(text_data)

Status: 🟡 Likely False Positive — one final static check

We should inspect that global hook before closing it because the exact CSP and any conditional logic matter.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\web.py | Select-Object -Skip 150 -First 40

If it confirms that nosniff and the CSP apply to the TXT response without an exception, we'll likely classify this Semgrep finding as false positive / mitigated by global response controls and move to the next Semgrep finding.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/44b60ffa604c7bbc1ed2eea116ccad292a94ab1a/Screenshot%202026-09-09%20124141.png)

That confirms the mitigation.

The app-wide response hook applies both:

resp.headers['Content-Security-Policy'] = csp

resp.headers['X-Content-Type-Options'] = 'nosniff'

and also adds:

resp.headers['X-Frame-Options'] = 'SAMEORIGIN'

resp.headers['X-XSS-Protection'] = '1; mode=block'

For the TXT-serving path, the most important control is X-Content-Type-Options: nosniff. That prevents the browser from reinterpreting a plain-text response as HTML based on its contents. The CSP adds another layer of protection.

Semgrep Finding 4 — Final classification

Potential XSS via make_response(text_data)

Status: False Positive / Mitigated 

Semgrep flagged the TXT book-serving response as a potential XSS risk because raw file content reaches make_response(). Manual review confirmed that TXT is an allowed upload type and that the response branch does not set security headers locally. However, an application-wide after_request hook applies X-Content-Type-Options: nosniff and a restrictive Content Security Policy to responses. These controls substantially mitigate browser content-sniffing and script execution, so the finding was classified as a false positive/mitigated condition.

The next useful one from your scan is the SHA1 usage in:

cps\api\i18n.py

SHA1 findings are often harmless when used for caching, identifiers, or non-security checksums, but serious if used for password hashing, signatures, or security-sensitive integrity.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\api\i18n.py | Select-Object -First 140

We’ll determine exactly what SHA1 is being used for and classify it as either:

false positive / non-security use,

weak cryptographic practice,

or a real security candidate.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/fc033fceb62115c14a093494debab8c545401641/Screenshot%202026-09-10%20085148.png)

This SHA1 finding is a clear false positive for security purposes.

Here, SHA1 is being used only to generate a content-based ETag for the translation catalog:

h = hashlib.sha1(locale.encode("utf-8"))
...
resp.set_etag(_catalog_etag(locale, catalog))

Its purpose is cache validation: if the translation content changes, the ETag changes and the client fetches a fresh copy. It is not being used for passwords, authentication, signatures, tokens, or security-sensitive integrity verification.

Semgrep Finding 5 — Final classification

SHA1 usage in cps\api\i18n.py

Status: False Positive / Non-security use 

For your Lab 4 notes:

Semgrep flagged SHA1 usage in the SPA internationalization endpoint. Manual review confirmed that SHA1 is used only to generate a deterministic ETag for HTTP cache revalidation of translation catalogs. It is not used for authentication, password storage, digital signatures, or other security-sensitive cryptographic purposes. The finding was therefore classified as a false positive for vulnerability purposes.

That finishes the last Semgrep finding I wanted us to manually inspect before moving forward.

CodeQL

We’re now at the point where I want to run CodeQL, triage anything materially different from what Semgrep/manual review found, then build the Lab 4 final candidate shortlist and start Lab 5.

First, from the project root, run: codeql database create .\codeql-db-calibre --language=python --source-root .\targets\Calibre-Web-NextGen --overwrite


![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/367ff915dd379d4ad8b8d9952db770232fe66efb/Screenshot%202026-09-10%20090514.png)

Yes — the CodeQL database creation completed successfully. The key final line is:

Successfully created database at C:\Users\eelve\Vulnerability-Research-Lab\codeql-db-calibre.

CodeQL processed 1,134 modules, imported the TRAP data, merged the relations, and finalized the database. The earlier Python-runtime messages did not prevent the build; CodeQL ultimately used Python 3.13.15 and completed extraction.

Next — run the CodeQL security analysis

From your main lab directory, run: codeql database analyze .\codeql-db-calibre codeql/python-queries:codeql-suites/python-security-extended.qls --format=sarif-latest --output=.\evidence\codeql-security-results.sarif --threads=1

This is the actual analysis phase: CodeQL database → security/quality queries → SARIF findings.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/5de860209f3ef0af110f9ae8241d65292d50a5fe/Screenshot%202026-09-10%20095059.png)

Excellent — the reduced-memory CodeQL security scan completed successfully. This time CodeQL loaded and evaluated all 52/52 security-focused queries, including path injection, command injection, XSS, SQL injection, LDAP injection, CSRF, open redirect, SSRF, unsafe deserialization, XXE, and others.

More importantly, CodeQL successfully scanned 981/981 Python files and 11/11 GitHub Actions files. That's solid coverage for our Lab 4 documentation.

Next step — see what CodeQL actually found

The terminal output shows that the analysis completed, but the actual alerts are stored in:

evidence\codeql-security-results.sarif

To extract the alerts cleanly Run: $results = Get-Content .\evidence\codeql-security-results.sarif -Raw | ConvertFrom-Json
$results.runs.results | Select-Object ruleId, level, message

Then we'll classify the CodeQL findings as we did with Semgrep. We only need to investigate findings that could materially change our Lab 4 candidate list; we do not need to chase every scanner warning before starting Lab 5.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/7b69cbc3b5c0a9153e8ac27dbf8bd833ea2aa98e/Screenshot%202026-09-10%20095201.png)

Now we have the actual CodeQL alert categories. There are a lot of results, but we are not going to investigate hundreds of alerts individually. Many are repeated instances of the same rule. For Lab 4, we want the findings most likely to represent a meaningful security issue.

CodeQL identified several especially interesting categories: dozens of path-injection flows, 8 reflected-XSS results, a SQL-injection result, 12 URL-redirection results, multiple SSRF results, and several other security categories. It also identified insecure TLS, insecure temporary-file use, ReDoS, Jinja autoescaping issues, certificate-validation issues, and overly permissive file permissions.

Importantly, CodeQL independently found multiple untrusted URL redirects, which supports the redirect concern we already found through Semgrep/manual review. It also found five full-SSRF flows and two partial-SSRF flows, which are new candidates worth checking before we close static analysis.

We're going to prioritize only these

SQL injection — highest priority because there's only one result and it could be significant.

SSRF — several potentially user-controlled outbound-request flows.

URL redirect — compare CodeQL's results against our existing HTTP_REFERER candidate.

Reflected XSS — inspect enough to determine whether there's a meaningful candidate.

Path injection — inspect representative/high-risk flows rather than all ~60.

Everything else gets documented/triaged only if it appears security-relevant.

The hundreds of py/log-injection alerts, for example, should not distract us from the higher-impact candidates right now.

CodeQL Finding #1 — SQL Injection

Let's start with the single SQL-injection result.

Run exactly this:

$results.runs.results | Where-Object { $_.ruleId -eq "py/sql-injection" } | ForEach-Object {

    $_.locations | ForEach-Object {
    
        [PSCustomObject]@{
        
            File = $_.physicalLocation.artifactLocation.uri
            
            Line = $_.physicalLocation.region.startLine
            
            Message = $_.message.text
            
        }
        
    }
    
} | Format-List

We isolated the single CodeQL SQL-injection candidate:

File: cps/admin.py

Line: 779

Rule: py/sql-injection

![Image alt](![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/215454f70664add31092ab59083ae5be8bbed76d/Screenshot%202026-09-10%20095550.png)

Now we need to see the surrounding code and determine where the SQL statement and its input come from.

Inspect admin.py around line 779

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\admin.py | Select-Object -Skip 745 -First 70

Don't test any payloads yet. First we'll trace:

User input → processing/validation → SQL construction → database execution

Then we'll classify this as either false positive, security-relevant but protected, or a candidate for controlled Lab 5 dynamic testing.

![Image alt](![Image alt](![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/41f56e781599c0d0fb5f520da2b343880713e383/Screenshot%202026-09-10%20095906.png))

This is a real static-analysis candidate, but we should not call it a confirmed SQL injection yet.

The important flow is:

GET /ajax/listusers

      ↓
      
order = request.args.get("order", "").lower()
      ↓
      
text(sort + " " + order)
      ↓
      
all_user.order_by(order)

There is a good control on sort: if the requested column is not a real User table column, it is reset to "id".

if sort not in ub.User.__table__.columns.keys():

    sort = "id"

But order does not receive equivalent validation:

order = request.args.get("order", "").lower()

if sort != "state" and order:

    order = text(sort + " " + order)

So a request-controlled value is being inserted into a SQLAlchemy text() expression. That is exactly why CodeQL flagged line 779.

There is also an important limitation: the route requires both authentication and the administrator role:

@user_login_required

@admin_required

So even if dynamic testing confirms SQL manipulation, we would still need to determine whether there is meaningful security impact beyond what an administrator can already do.

Current classification

CodeQL SQL Injection — VALID FOR LATER DYNAMIC TESTING 🟠

CodeQL identified a potential SQL injection path in the administrative user-list endpoint. Manual review showed that the requested sort column is validated against known database columns, while the user-controlled order parameter is incorporated into a SQLAlchemy text() expression without an equivalent allowlist. Because the endpoint requires administrator privileges and practical SQL manipulation has not yet been demonstrated, the finding remains a static-analysis candidate pending controlled local validation.

One more static check

Before Lab 5, let's determine what values the application's frontend normally sends for order.

Run: Get-ChildItem .\targets\Calibre-Web-NextGen -Recurse -File | Select-String -Pattern "ajax/listusers|listusers" | Select-Object Path, LineNumber, Line

This searches the entire Calibre-Web NextGen source tree for references to the /ajax/listusers endpoint.We'll use it to determine what the frontend normally supplies for the order parameter before moving to the next CodeQL candidate.

![Image alt](![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/f40b50b95599fff1cfa361958d9b0f07ac6ca15e/Screenshot%202026-09-10%20100725.png)

The search confirms the endpoint is referenced in cps\static\js\table.js, especially around line 1210. That's the frontend code we need.

Inspect the frontend request

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\static\js\table.js | Select-Object -Skip 1190 -First 45

We're specifically looking for how the table sends sort and order to /ajax/listusers.

If we see that the UI normally restricts order to something like asc or desc, that establishes the intended input. But remember: frontend restrictions alone would not protect the server, because a client can send HTTP parameters directly.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/6de5a1e4c559278f00c53128e481efdfaeb4f6eb/Screenshot%202026-09-10%20101300.png)

That section of table.js does not show the /ajax/listusers request yet. It’s handling bulk user-table actions.

The search results showed another likely reference around line 1320, so inspect that area next.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\static\js\table.js | Select-Object -Skip 1300 -First 55

We’re looking for the table configuration that sends values such as:

sort

order

offset

limit

search



That still isn’t the /ajax/listusers table request. We’re close, but instead of guessing line ranges again, let’s jump directly to the exact match.

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\static\js\table.js -Pattern 'ajax/listusers' -Context 8,12

That will show the matching line plus 8 lines before and 12 lines after it.

![Image alt](https://github.com/Kevinolee1/Static-Analysis/blob/d3b2f44559c8307c357bea032eeb95cbeb52a61e/Screenshot%202026-09-10%20101530.png)

That result tells us the exact string ajax/listusers is not present in table.js. The earlier broad search likely matched just listusers in a different form or generated URL logic.

Let’s search only for the word listusers and show context.

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\static\js\table.js -Pattern 'listusers' -Context 10,15

That should reveal the actual table configuration or URL-building logic tied to the admin user list.



Good — that confirms those table.js matches are for editlistusers, not the GET endpoint CodeQL flagged. So the normal /ajax/listusers request is probably wired from the HTML template through Bootstrap Table rather than hard-coded in this JavaScript file.

Inspect the user-table template

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\templates\*.html -Pattern 'user-table|listusers' -Context 5,10

We’re looking for something like:

data-url="..."

data-sort-name="..."

data-sort-order="..."

That should tell us the intended frontend values for sort and order.

Perfect. This confirms how /ajax/listusers is connected to the frontend:

<table id="user-table"
    
       ...
       
       data-url="{{url_for('admin.list_users')}}"
       
       ...
       
>

So Bootstrap Table generates the offset, limit, search, sort, and order parameters automatically. The template also marks columns as sortable. The important security point remains unchanged: the browser UI is not a security boundary. An authenticated administrator could send a modified order parameter directly.

SQL candidate static-analysis result

We now have enough static evidence to keep this candidate for Lab 5:

GET /ajax/listusers

        ↓
        
request.args["order"]

        ↓
        
.lower()

        ↓
        
NO server-side asc/desc allowlist

        ↓
        
text(sort + " " + order)

        ↓
        
SQLAlchemy order_by()

Meanwhile, sort does have a server-side allowlist:

if sort not in ub.User.__table__.columns.keys():

    sort = "id"

That difference is exactly what makes order interesting.

Classification: 🟠 Potential SQL Injection / SQL Expression Injection — Dynamic validation required.

It is not a confirmed vulnerability, and because /ajax/listusers requires @admin_required, even successful SQL manipulation would need a meaningful security impact assessment.


CodeQL identified a potential SQL injection path in the administrative user-list endpoint. Manual tracing confirmed that the requested sort column is validated against known database columns, while the request-controlled order parameter is incorporated into a SQLAlchemy text() expression without an equivalent server-side allowlist. The normal frontend uses Bootstrap Table to construct the request, but client-side behavior does not constitute server-side validation. Because the endpoint requires administrator privileges and exploitability has not been demonstrated, the finding remains a candidate for controlled local dynamic testing.

CodeQL SSRF

Now let's inspect the five full-SSRF candidates instead of spending more time on this one.

Run:

$results.runs.results | Where-Object { $_.ruleId -eq "py/full-ssrf" } | ForEach-Object {

    $_.locations | ForEach-Object {
    
        [PSCustomObject]@{
        
            File = $_.physicalLocation.artifactLocation.uri
            
            Line = $_.physicalLocation.region.startLine
            
        }
        
    }
    
} | Format-Table -AutoSize

We'll see whether those five alerts collapse into one or two underlying request flows.



the five full-SSRF alerts collapse into just two files:

cps/admin.py   1900

cps/admin.py   1921

cps/admin.py   3526

cps/admin.py   3575

cps/helper.py  2124

That means we can review the underlying flows instead of treating them as five separate issues.

Next step — inspect the first admin.py SSRF block

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\admin.py | Select-Object -Skip 1870 -First 80

We’re looking for:

user-controlled URL or host
        ↓
validation / allowlist / normalization
        ↓
requests.get / post / session request
        ↓
response handling

we’ll decide whether the two findings around 1900 and 1921 are the same underlying SSRF path and whether they’re worth carrying into Lab 5.



This is a strong SSRF candidate, but the context matters a lot.

The flow is:

admin-supplied OAuth/OIDC URL

        ↓
        
metadata_url / server_url

        ↓
        
requests.get(...)

        ↓
        
server makes outbound request

For example:

metadata_url = to_save.get("config_generic_oauth_metadata_url", "")
...
resp = requests.get(metadata_url, timeout=3, verify=constants.OAUTH_SSL_STRICT)

and:

update["oauth_base_url"] = to_save["config_generic_oauth_server_url"]

resp = requests.get(

    os.path.join(update["oauth_base_url"], ".well-known/openid-configuration"),
    
    timeout=3,
    
    verify=constants.OAUTH_SSL_STRICT
    
)

There is no visible host allowlist, scheme restriction, or private-IP check in this function. So CodeQL is correctly seeing a server-side request whose destination comes from configuration input.

However, this appears to be part of OAuth/OIDC administration, and products normally need to let an administrator configure an identity-provider URL. If only administrators can reach the configuration path, the security impact may be limited or considered intended functionality.

Current classification

🟠 Potential SSRF through OAuth/OIDC configuration — needs authorization-context review

Not confirmed vulnerability yet.

CodeQL identified server-side requests to administrator-supplied OAuth/OIDC metadata and server URLs. Manual review confirmed that these URLs are passed to requests.get() without an explicit destination allowlist or private-network restriction in the reviewed helper. Because the functionality appears intended to support administrator-configured identity providers, exploitability and security impact depend on which users can modify these settings and whether administrative SSRF is considered within the application's threat model.

Find who can call this helper

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\admin.py -Pattern "_configuration_oauth_helper\(" -Context 8,12

That will tell us whether these SSRF paths are strictly behind @admin_required or reachable through some lower-privileged configuration flow.



We’ve confirmed _configuration_oauth_helper() is called from the main configuration-saving flow around line 3004.

Now we need to inspect the route/decorators for that configuration function to see who is authorized to reach it.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\admin.py | Select-Object -Skip 2890 -First 150

We’re looking for the function definition above that block and decorators such as:

@user_login_required

@admin_required

If it is strictly admin-only, we’ll likely classify this SSRF as admin-configured / lower-priority rather than a strong vulnerability candidate.



We still don’t have the route decorators. The snippet starts inside the configuration function, so we need to go a little farther up.

Run this: Get-Content .\targets\Calibre-Web-NextGen\cps\admin.py | Select-Object -Skip 2810 -First 90



We found the helper itself, but still not the route that invokes it. The next static check is simply to identify every caller of _configuration_update_helper().

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\admin.py -Pattern "_configuration_update_helper\(" -Context 8,12

That should finally show the route and decorators around the configuration save path. If it is protected by @admin_required, we can classify these OAuth/OIDC SSRF findings as administrator-controlled and lower priority and move on to the next SSRF location.


That confirms the important part: the configuration update endpoint is admin-only.

The relevant route is:

@admi.route("/admin/ajaxconfig", methods=["POST"])

@user_login_required

@admin_required

def ajax_config():

    return _configuration_update_helper()

So the OAuth/OIDC SSRF path requires an authenticated administrator to submit the configuration. That makes this much less compelling as a vulnerability because configuring an external identity provider inherently requires the server to contact an administrator-specified URL.

Classification for these first two SSRF findings

I would mark the findings around admin.py:1900 and 1921 as:

Low-priority / likely intended administrative functionality

CodeQL identified potential SSRF paths in the generic OAuth/OIDC configuration logic. Manual tracing confirmed that administrator-controlled metadata and server URLs are passed to requests.get() without explicit private-address filtering. However, the request path is protected by both authentication and administrator-role checks, and outbound requests are part of the intended identity-provider configuration workflow. The finding was therefore deprioritized pending evidence of a meaningful security boundary violation.

We do not need to carry this one into Lab 5 unless something else later changes our assessment.

Now let’s inspect the next CodeQL SSRF pair at admin.py:3526 and 3575.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\admin.py | Select-Object -Skip 3490 -First 110




These two CodeQL findings at admin.py:3526 and 3575 are also clearly administrator-only OIDC test functions.

The first path is:

@admi.route("/admin/test_oidc", methods=["POST"])

@user_login_required

@admin_required

def test_oidc():

    url = request.get_json().get('url')
    
    ...
    
    response = requests.get(discovery_url, timeout=5, verify=constants.OAUTH_SSL_STRICT)

The second is:

@admi.route("/admin/test_metadata", methods=["POST"])

@user_login_required

@admin_required

def test_metadata():

    metadata_url = request.get_json().get('url')
    
    ...
    
    response = requests.get(metadata_url, timeout=5, verify=constants.OAUTH_SSL_STRICT)

CodeQL is technically correct that user-controlled URLs reach requests.get(), but both routes require:

Authenticated user

        ↓
        
Administrator role

        ↓
        
OIDC connection-testing feature

        ↓
        
Server intentionally contacts supplied URL

There is also no visible private-IP filtering or destination allowlist, but because the explicit purpose of these endpoints is to let an administrator test an identity-provider URL, I would deprioritize both.

Classification

Likely intended administrative functionality / low-priority SSRF

We now have:

admin.py:1900  → Admin OAuth configuration     → Deprioritize

admin.py:1921  → Admin OIDC configuration      → Deprioritize

admin.py:3526  → Admin OIDC test endpoint      → Deprioritize

admin.py:3575  → Admin metadata test endpoint  → Deprioritize

That leaves the more interesting one:

cps/helper.py:2124

This one matters more because we haven't established its authorization boundary yet.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\helper.py | Select-Object -Skip 2085 -First 85

We'll trace helper.py:2124 and determine whether this fifth SSRF alert is materially different from the four admin-only findings.



This fifth SSRF finding is already much more interesting than the four admin-only OIDC results, because the code contains an explicit SSRF defense.

The important branch is:

if cli_param.allow_localhost:
    img = requests.get(url, timeout=(10, 30), allow_redirects=True, stream=True)
elif use_advocate:
    img = cw_advocate.get(url, timeout=(10, 30), allow_redirects=True, stream=True)
else:
    ...

And the developer comment directly says:

# advocate path stays SSRF-safe under redirects because validation

# happens per-connection ...

So CodeQL is probably flagging the raw requests.get() branch, while the normal protected path appears to use advocate, which is specifically intended to prevent SSRF to local/private destinations.

The key question is now:

When can cli_param.allow_localhost be enabled, and is that an intentional administrator/startup option?

If it is an explicit command-line option such as “allow localhost cover downloads,” then this may be a deliberate security bypass/configuration feature, not a vulnerability.

Find where allow_localhost is defined and documented Run: Get-ChildItem .\targets\Calibre-Web-NextGen\cps -Recurse -File | Select-String -Pattern "allow_localhost" | Select-Object Path, LineNumber, Line


we can determine whether helper.py:2124 is:

A. a genuine SSRF candidate,

B. a protected flow that CodeQL cannot understand, or

C. an intentional opt-in localhost allowance.


shows only three references:

cps\cli.py      line 30    self.allow_localhost = None
cps\cli.py      line 119   self.allow_localhost = args...
cps\helper.py   line 2123  if cli_param.allow_localhost:

So the next thing we need is the actual command-line definition around cli.py:119. That will tell us whether this is an intentional opt-in setting.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\cli.py | Select-Object -Skip 95 -First 40

We want to see whether allow_localhost is an explicit command-line switch and how it is described.

If it shows something like an explicit --allow-localhost option, we'll determine exactly what that option permits before deciding whether CodeQL's helper.py:2124 SSRF finding survives Lab 4.


That screenshot explains it: our range started too late. We’re seeing certificate/key handling, but not the line where allow_localhost is assigned.

Since your earlier search identified line 119, let’s target that exact area with line numbers.

Run: Get-Content .\targets\Calibre-Web-NextGen\cps\cli.py | Select-Object -Skip 110 -First 20

We specifically want the code around:

self.allow_localhost = ...

Once we see what args or environment variable controls it, we’ll trace where that argument itself is defined. Then we can make the final call on the helper.py:2124 SSRF finding.

This gives us the key information.



The screenshot shows:

# load covers from localhost
self.allow_localhost = args.l or os.environ.get("CALIBRE_LOCALHOST", None)

So allow_localhost is not normally enabled automatically. It is controlled either by the command-line argument args.l or the CALIBRE_LOCALHOST environment variable.

That strongly suggests the raw requests.get() behavior in helper.py is an intentional opt-in mode. When it isn't enabled, the application instead uses cw_advocate.get(), which the code explicitly describes as the SSRF-protected path.

Before we close the finding, let's verify exactly what the -l argument tells the administrator it does.

Run: Select-String -Path .\targets\Calibre-Web-NextGen\cps\cli.py -Pattern "add_argument.*-l" -Context 2,4

That should give us enough evidence to make the final classification for CodeQL SSRF #5.




This confirms the intended behavior.

The important line is:

parser.add_argument('-l', action='store_true',

                    help='Allow loading covers from localhost')

Combined with what we already traced:

self.allow_localhost = args.l or os.environ.get("CALIBRE_LOCALHOST", None)

and:

if cli_param.allow_localhost:

    img = requests.get(...)
    
elif use_advocate:

    img = cw_advocate.get(...)
    
Final classification — helper.py:2124

CodeQL SSRF alert: Deprioritized / intentional opt-in behavior.

The application normally routes remote cover retrieval through its SSRF-protected advocate path. The raw requests.get() branch becomes available when the operator explicitly enables loading covers from localhost using -l or the corresponding environment setting.

So we should not call this a vulnerability based on the static evidence.

CodeQL identified a potential SSRF path in remote cover retrieval. Manual tracing showed that the application normally uses an SSRF-protected request mechanism. Direct requests capable of reaching localhost are enabled only when the operator explicitly activates the -l option (“Allow loading covers from localhost”) or corresponding environment configuration. The finding was therefore classified as intentional opt-in behavior rather than a vulnerability.


**SSRF triage complete**

All five py/full-ssrf results have now been reviewed. None currently deserves promotion to our Lab 5 candidate list.

Our more promising CodeQL categories remain reflected XSS, URL redirection, and selected path-injection findings. We already have the Semgrep HTTP_REFERER redirect candidate, so CodeQL's redirect results may corroborate that one rather than create a new candidate.

