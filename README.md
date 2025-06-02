# Automated Email Phishing Checker

This UiPath automation is designed to help detect potential phishing emails in an inbox by analyzing sender domains, email content, attachments, and leveraging the VirusTotal API for URL reputation checks. It runs continuously, periodically checking for new emails.

## Features

-   **Continuous Monitoring:** Automatically checks for new unread emails in a specified inbox at a configurable interval (default: every 30 seconds).
-   **VirusTotal Integration:** Extracts URLs from email bodies and submits them to the VirusTotal API for reputation analysis, checking for known malicious links.
-   **Sender Analysis:** Evaluates sender domains against predefined trusted lists to identify potential spoofing or unauthorized senders.
-   **Content Analysis:** Scans email subjects and bodies for suspicious keywords and phrases commonly used in phishing attempts.
-   **Attachment Scrutiny:** Identifies potentially dangerous attachment file extensions.
-   **Phishing Scoring:** Calculates a "phishing score" for each email based on detected indicators, allowing for configurable sensitivity.
-   **Automated Action:** Automatically moves identified phishing emails to a designated quarantine folder within your email client.
-   **Alerting:** Sends email alerts to a specified security team or administrator when a phishing email is detected.

## Prerequisites

Before running this automation, ensure you have the following:

-   **UiPath Studio** (Classic Experience profile recommended for this project's setup).
-   **UiPath Robot** (Attended for manual runs, Unattended for continuous background operation).
-   **UiPath.Mail.Activities** package installed in your project.
-   **UiPath.Web.Activities** package installed in your project.
-   **A VirusTotal API Key**: A free public key can be obtained by joining the [VirusTotal Community](https://www.virustotal.com/gui/join-us).

## Setup and Configuration

### 1. Open the Project

1.  Clone this repository to your local machine using Git:
    ```bash
    git clone [https://github.com/roshanprabu/phishing-email-checker.git](https://github.com/roshanprabu/phishing-email-checker.git)
    ```
2.  Open the project in UiPath Studio. The main workflow file is `Main.xaml`.

### 2. Configure Email Access

The automation is configured to use Outlook by default.
-   Open the `Main.xaml` workflow.
-   Locate the **"Get Outlook Mail Messages"** activity.
-   Ensure the `Account` property is set correctly for your Outlook profile (if you use multiple accounts).
-   Verify the `MailFolder` property is set to `"Inbox"`.
-   The automation checks `OnlyUnreadMessages` by default to avoid reprocessing emails.

### 3. Change VirusTotal API Key

Your VirusTotal API key is critical for URL reputation checks.

**Method 1: Directly in Variables (Recommended for Development/Testing)**
1.  In UiPath Studio, open the `Main.xaml` workflow.
2.  Go to the **Variables** panel (usually at the bottom of the Studio window).
3.  Find the variable named `virusTotalApiKey` (Variable Type: `String`).
4.  In the `Default Value` column, replace the placeholder key with your actual VirusTotal API key.
    ```
    "YOUR_VIRUSTOTAL_API_KEY_HERE"
    ```
    *(Make sure to keep the double quotes.)*

**Method 2: Using UiPath Orchestrator Asset (Recommended for Production & Security)**
For production deployments, it's best practice to avoid hardcoding sensitive information directly in your workflow files.
1.  In UiPath Orchestrator, navigate to the `Assets` section.
2.  Create a new **Credential** or **Text** Asset (e.g., name it `VirusTotalApiKey`).
3.  Store your VirusTotal API key in this Asset.
4.  In your `Main.xaml` workflow, replace the `virusTotalApiKey` variable's direct assignment with a **"Get Credential"** or **"Get Asset"** activity to retrieve the key securely at runtime.

### 4. Change Security Alerts Email Address

When a potential phishing email is detected, an alert can be sent to a designated security team or administrator.

1.  In UiPath Studio, open the `Main.xaml` workflow.
2.  Locate the **"Send Outlook Mail Message"** activity that is within the "If (Phishing Detected)" branch (the final decision block for flagged emails).
3.  In the **Properties** panel of this activity, modify the `To` property to your desired security alert email address (e.g., `"your.security.team@example.com"`).
    ```
    "your.security.team@example.com"
    ```
    *(Make sure to keep the double quotes.)*

### 5. Adjust Trusted Domains and Suspicious Keywords

To fine-tune the detection logic, you can modify the lists of trusted sender domains and suspicious keywords.

1.  In UiPath Studio, open the `Main.xaml` workflow.
2.  Go to the **Variables** panel.
3.  Find the `trustedDomains` variable (Variable Type: `List<String>`). Modify its `Default Value` to include domains you explicitly trust (e.g., your company's domain, well-known legitimate services).
    ```vb.net
    New List(Of String) From {"yourcompany.com", "trustedpartner.com", "microsoft.com"}
    ```
4.  Find the `suspiciousKeywords` variable (Variable Type: `List<String>`). Modify its `Default Value` to include phrases commonly found in phishing attempts.
    ```vb.net
    New List(Of String) From {"urgent", "immediate action required", "account suspended", "verify your details", "password expired", "invoice overdue"}
    ```

### 6. Adjust Phishing Score Thresholds

The `phishingScore` determines how sensitive the detection is.
-   Review the `Assign` activities where `phishingScore` is incremented. Adjust the values based on how strongly each indicator should contribute to a phishing detection.
-   Locate the final `If` activity that decides whether an email is phishing. Its condition typically checks `isPhishingEmail = True OR phishingScore >= X`. Adjust `X` (the threshold number) as needed.

### 7. Adjust Polling Interval

The automation checks for new emails every 30 seconds by default.

1.  In UiPath Studio, open the `Main.xaml` workflow.
2.  Locate the **"Delay"** activity at the very end of the main `While (Condition: True)` loop.
3.  Modify its `Duration` property to your desired interval (e.g., `"00:00:10"` for 10 seconds, or `"00:01:00"` for 1 minute).
    ```
    "00:00:30"
    ```

## Running the Automation

1.  After configuring the project, ensure all changes are saved (`Ctrl + S`).
2.  In UiPath Studio, click **"Run File"** or **"Debug File"** to test the automation.
3.  For continuous, unattended operation, publish the project to UiPath Orchestrator and create a Job.

## Troubleshooting

-   **"Object reference not set to an instance of an object."**
    -   Carefully check all variables for `Nothing` values, especially `suspiciousKeywords` (ensure it's initialized).
    -   Verify that `currentMail` in the main "For Each MailMessage" loop is correctly typed as `System.Net.Mail.MailMessage`.
    -   Ensure robust null/empty string checks (e.g., `String.IsNullOrWhiteSpace`) are used in `If` conditions before accessing string methods.
    -   When deserializing JSON, ensure you handle cases where expected properties might be `Nothing` (use `JObject.SelectToken("path.to.property") IsNot Nothing`).
-   **VirusTotal API Errors / Rate Limits:**
    -   Monitor the Output panel for error messages from the "HTTP Request" activities.
    -   Ensure your VirusTotal API key is correct and active.
    -   If you frequently hit rate limits (VirusTotal's public API has limits), consider adding more `Delay` time before the second API call to space out requests, or explore VirusTotal's private API for higher usage.
-   **Emails not moving / Alerts not sending:**
    -   Verify your email client settings and that the `Phishing_Quarantine` folder exists.
    -   Double-check the `To` and `From` addresses in "Send Outlook Mail Message" activities.
    -   Confirm that your `phishingScore` thresholds are set correctly and are being met for test emails.
    -   Ensure the `MarkAsRead` property of `Move Mail Message` is set to `True` for processed emails.

---