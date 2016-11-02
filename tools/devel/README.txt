
The following is adapted from:

- https://github.com/dart-lang/HOWTO-workflows/wiki/Code-Reviews-for-github-with-rietveld
- http://www.chromium.org/developers/how-tos/install-depot-tools

# Code review workflow for Rekall.

## Step 1: Clone the project

    > git clone https://github.com/google/rekall.git

## Step 2a: Clone the depot_tools repository somewhere.

    > git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git

## Step 2b: Add the depot_tools directory to your path (This will add the git cl
   command).

    > export PATH="`pwd`/depot_tools/:$PATH"

## Step 2c: Configure git cl, you'll only need to do this once.
    > git cl config
    > Rietveld server (host[:port]) [https://codereview.appspot.com]:
    > CC list:rekall-dev@googlegroups.com
    > Private flag (rietveld only):
    > Tree status URL:
    > ViewVC URL:

## Step 2d: Authenticate with Google.
    > depot-tools-auth login https://codereview.chromium.org

## Step 3: Create a branch for your new changes

Pick a branch name not existing locally nor in the remote repo, we recommend
that you use your user name as a prefix to make things simpler.

    > git checkout -b uname_example                        # new branch

## Step 4a: Do your changes and commit them locally in git

    > echo "file contents" > awesome_example.txt
    > git add awesome_example.txt
    > git commit -a -m "An awesome commit, for an awesome example."

## Step 4b: Rebasing your tracking branch

If in step 4a you get a notification that "you may need to rebase your tracking
branch", try running:

    > git pull origin master

## Step 5: Upload CL using 'git cl'

    > git cl upload origin/master

Then click on the `publish & mail` link to send email to the reviewers from the
rietveld website. Note that double "git status -s" codes, e.g.
AM (Added Modified) can cause rietveld to show "error: old chunk mismatch".

## Step 6: Make code review changes and publish new versions of your code

    > echo "better file contents" > awesome_example.txt
    > git commit -a -m "An awesomer commit"
    > git cl upload origin/master

## Step 7: Sync up to latest changes

If new changes have been made to the repo, you need sync up to the new changes
before submitting your code:

    > git pull origin master
    > git cl upload origin/master

## Step 8: Submit your changes

We use git-cl also to submit. We use 'git cl push', to squash all commits from
the branch into a single commit in git.

    > git cl push origin/master

This command will close the issue in Rietveld and submit your code directly on
master.

## Step 9: Clean up the mess

After submitting, you can delete your local branch so that the repo is clean and
tidy :)

    > git checkout master
    > git branch -D uname_example    # delete local branch

You can also see which branches are currently under review or have been
reviewed:

    > git cl status

## Step 10: Goto step 3
