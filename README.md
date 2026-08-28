# CI/CD Compliance and Quality Linter

A tool that automatically checks a software project's code for security and compliance problems every time a change is made/pushed to the main git branch and blocks that change from being merged if problems are found.

---

## 1. Overview

**Name:** CI/CD Compliance and Quality Linter

**Description:** An automated scanner that reviews every code change in a software project for common security mistakes, such as accidentally exposed passwords or unsafe web connections, and stops the change from being accepted until the problem is fixed. Each issue it finds is linked to a specific requirement from two widely used security standards, ISO/IEC 27001 and SOC 2, so the results can also be used as evidence during a compliance audit.

---

## 2. The Problem This Solves

Organizations needing to meet security requirements like ISO/IEC 27001 or SOC 2 need to prove that all code changes are thoroughly checked before deployment. Typically, this check happens manually: someone goes through the code modifications and looks for clear errors.

This manual review process has three main drawbacks:

- It takes a long time, which slows down how quickly teams can release new versions.
- It lacks uniformity, because different people reviewing the code will spot different issues.
- It often fails to find problems. A password or access key accidentally left within a large amount of code changes can easily be missed by a human reviewer. This oversight could then allow an attacker to gain access to company systems.

Here are common errors this tool is designed to detect:

- A password, API key, or other private credential written directly into the code instead of being kept in a secure location.
- Software components that are not set to a specific, tested version, meaning an update to that part could introduce unverified or malicious changes without anyone noticing.
- An internet connection that transmits data without encryption, making it possible for that data to be intercepted.

---

## 3. How This Tool Solves It

This tool functions as an automated check that activates whenever someone suggests a code alteration. It performs this review before that change can become part of the main branch/project.

1. **Automatic scanning.** When a code change is proposed, the tool examines every file within the project, searching for the previously outlined patterns.
2. **Clear reporting.** If it finds an issue, it creates a report that shows the exact file and line number where the problem is located, how severe it is and the necessary steps for a fix.
3. **Compliance mapping.** Each detected problem connects to a specific section of ISO/IEC 27001 or SOC 2. This means the report can serve directly as audit proof, eliminating the need for later translation.
4. **Blocking unsafe changes.**  If a serious issue is uncovered, the tool prevents the change from being merged until it has been corrected. This removes the need for a person to remember to catch the problem.
5. **Audit trail.** Every scan can also generate a downloadable report in a structured format. This allows results to be saved, monitored over time, or integrated into other compliance or security management systems.

In short: This system changes a manual, irregular inspection into an automated, reliable one. It then converts the results from that inspection into compliance paperwork that is ready for use.

---

## 4. What the Tool Checks

| Check | What It Looks For | Why It Matters | Related Standard |
|---|---|---|---|
| Exposed AWS credentials | The pattern of Amazon Web Services access keys appearing directly in program code | An outsider could gain access to the company's cloud infrastructure if a key is exposed | ISO/IEC 27001 Annex A.8.24; SOC 2 CC6.1 |
| Exposed general secrets | Passwords, API keys or access tokens that are hardcoded into the program  | This carries the same risk as above, but for more general information | ISO/IEC 27001 Annex A.8.24; SOC 2 CC6.1 |
| Unlocked software components | A dependency listed without a specific version number | An update that has not been tested or that is compromised might be brought in automatically | ISO/IEC 27001 Annex A.8.25; SOC 2 CC8.1 |
| Unencrypted web connections | A web address that starts with "http" instead of the secure "https" | Data transmitted over this type of connection can be intercepted by others | ISO/IEC 27001 Annex A.8.20; SOC 2 CC6.6 |

---

## 5. How to Use the Code

This setion explains how to use this repo, what to download, explains what each command is and does at each stage. No prior experience is assumed.

### What you need before starting

- A computer with Python installed. 
- The project folder itself. This is everything inside cicd-compliance-linter, the entire folder without leaving a single file. It contains the tool's code, its tests and its setup instructions all together. So it needs to be downloaded.

### Step 1: Get the project folder onto your computer

**Open the project.** Download the cicd-compliance-linter folder (or the zip file containing it) and unzip it somewhere you can find easily, such as your Downloads or Desktop folder. Then open that folder in a code editor that supports python such as PyCharm or open a Terminal window and navigate into it.

### Step 2: Create a separate, contained workspace for the project

**Create an isolated environment for the project.** Every Python project should run inside its own isolated workspace, so the components it needs do not clash with anything else already on your computer. Type the following two lines into the terminal, one at a time:
   ```
   python3 -m venv .venv
   source .venv/bin/activate
   ```
**What this does:** the first line creates a new, empty workspace named .venv inside the project folder. The second line switches your terminal into that workspace, so anything you install next stays contained there instead of affecting the rest of your computer. You will need to run the second line again each time you reopen the terminal to work on this project.

### Step 3: Install what the tool needs to run
   ```
   pip install -r requirements.txt
   ```
**What this does:** the project folder contains a file named requirements.txt, which is simply a list of the smaller tools this project depends on in order to run (for example, the tool that formats the results into a readable table). This command reads that list and installs everything on it automatically, in one step.

### Step 4: Run the scan
   ```
   python main.py --path .
   ```
   This scans the current folder and prints a report directly to the screen.

**What this does:** main.py is the file that starts the tool. Running it tells the tool "scan the code starting from this folder" (--path . means "this current folder"). Within a few seconds, a report will print directly in your terminal, listing anything it found and explaining why it matters.

### Step 5 (optional): Save the results as a file instead of only viewing them on screen
   ```
   python main.py --path . --output-json audit.json
   ```
**What this does:** this runs the exact same scan as above, but additionally saves a copy of the results into a new file named audit.json inside the project folder. This is useful if you want to keep a record of a scan, share it with someone else, or attach it as evidence later — for example, in a compliance audit.

### Step 6 (optional): Confirm the tool itself is working correctly
   ```
   pytest tests/ -v
   ```
   This confirms that the tool correctly detects each type of problem it is designed to catch.

**What this does:** the project includes its own built-in tests, kept in the tests folder. This command runs all of them and tells you whether the tool is correctly catching the problems it is designed to catch. You do not need to run this to use the tool day-to-day — it exists mainly to prove, to yourself or anyone reviewing the project, that it works as claimed.

### Step 7 (optional): Upload the project to GitHub so it runs automatically

The folder already includes two automation files (inside .github/workflows), so once the project is on GitHub, no further setup is needed — they start working immediately:

- One automatically runs the scan every time a change is proposed to the project and blocks that change from being accepted if a serious problem is found.
- One automatically re-runs the tests from Step 6, to confirm the tool itself has not broken.

To upload the project, create an empty, blank repository on GitHub first (do not add a README or any files to it), then run the following from inside the project folder, one line at a time:
```
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin YOUR-REPOSITORY-LINK-HERE
git push -u origin main
   ```
**What this does, line by line:**
- git init — starts tracking this folder as a project.
- git add . — selects every file in the folder to be saved.
- git commit -m "Initial commit" — takes a snapshot of everything selected, with a short label describing it.
- git branch -M main — names the main line of the project "main," which is GitHub's expected name.
- git remote add origin ... — points this folder at the empty repository you created on GitHub (replace YOUR-REPOSITORY-LINK-HERE with the link GitHub gives you when you create the repository).
- git push -u origin main — uploads everything to GitHub.

Once this finishes, open the repository on GitHub and click the "Actions" tab, you should see both automated checks running on their own within a minute or two.

### Reading the result

After any scan, there are only two possible outcomes:

- **Pass:** no problems were found. The report says so directly, and the change is safe to proceed.
- **Fail:** one or more problems were found. For each one, the report shows exactly which file and line it is on, how serious it is, which compliance rule it relates to and a plain-language explanation of how to fix it.

---

## 6. Notes and Limitations

- This tool identifies problems by recognising known patterns. It is a strong first layer of defence but is not a complete substitute for a full security review, particularly for more sophisticated or well-disguised issues.
- A small set of files used only for testing the tool are deliberately excluded from its own compliance scan, since they intentionally contain example problems used to confirm the tool is working.
- The tool currently checks two common types of dependency files (requirements.txt and package.json). Other formats may be added in future.



