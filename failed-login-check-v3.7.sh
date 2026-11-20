#!/bin/bash

LOGFILE="/var/log/auth.log"
REPORT_DIR="/var/log/ssh-security-reports"
THRESHOLD=3
ACCOUNT_THRESHOLD=3

# Check that the authentication log is readable
if [[ ! -r "$LOGFILE" ]]; then
    echo "ERROR: Cannot read authentication log."
    exit 4
fi

# Create report directory
if ! mkdir -p "$REPORT_DIR"; then
    echo "ERROR: Cannot create report directory."
    exit 4
fi

REPORT_TIME=$(date "+%Y%m%d_%H%M%S")
REPORT_FILE="$REPORT_DIR/ssh-report-$REPORT_TIME.txt"

CUTOFF=$(date -d "24 hours ago" "+%Y-%m-%dT%H:%M:%S")

# Preserve the exit status returned by AWK through tee
set -o pipefail

awk -v cutoff="$CUTOFF" \
    -v threshold="$THRESHOLD" \
    -v account_threshold="$ACCOUNT_THRESHOLD" '

/sshd-session\[[0-9]+\]: Failed password/ {

    timestamp=$1

    if (timestamp < cutoff)
        next

    user=""
    ip=""
    total_attempts++

    for (i=1; i<=NF; i++) {
        if ($i == "for") {
            if ($(i+1) == "invalid")
                user=$(i+3)
            else
                user=$(i+1)
        }

        if ($i == "from")
            ip=$(i+1)
    }

    if (user != "" && ip != "") {
        count[user,ip]++
        ip_attempts[ip]++
        last_seen[user,ip]=timestamp
        accounts[ip,user]=1
        source_ips[ip]=1
        unique_users[user]=1
    }
}

END {
    highest_severity="NONE"
    repeated_alerts=0
    account_alerts=0

    top_ip=""
    top_attempts=0

    for (ip in ip_attempts) {
        if (ip_attempts[ip] > top_attempts) {
            top_attempts=ip_attempts[ip]
            top_ip=ip
        }
    }

    print "======================================="
    print "       SSH SECURITY REPORT - V3.7"
    print "======================================="
    print "Generated:", strftime("%c")
    print "Analyzing failed logins since:", cutoff
    print "Time window: Last 24 hours"
    print "======================================="

    print ""
    print "DETECTION DETAILS"
    print "---------------------------------------"

    for (key in count) {
        split(key, fields, SUBSEP)

        if (count[key] >= threshold) {
            severity="LOW"

            if (count[key] >= 10)
                severity="HIGH"
            else if (count[key] >= 5)
                severity="MEDIUM"

            if (severity == "HIGH")
                highest_severity="HIGH"
            else if (severity == "MEDIUM" && highest_severity != "HIGH")
                highest_severity="MEDIUM"
            else if (severity == "LOW" && highest_severity == "NONE")
                highest_severity="LOW"

            repeated_alerts++

            print "ALERT: Repeated login failures!"
            print "Severity:", severity
            print "Target account:", fields[1]
            print "Source IP:", fields[2]
            print "Failed attempts:", count[key]
            print "Last observed:", last_seen[key]
            print "---------------------------------------"
        }
    }

    for (entry in accounts) {
        split(entry, fields, SUBSEP)
        account_count[fields[1]]++
        account_list[fields[1]]=account_list[fields[1]] " " fields[2]
    }

    for (ip in account_count) {
        if (account_count[ip] >= account_threshold) {
            severity="LOW"

            if (account_count[ip] >= 10)
                severity="HIGH"
            else if (account_count[ip] >= 5)
                severity="MEDIUM"

            if (severity == "HIGH")
                highest_severity="HIGH"
            else if (severity == "MEDIUM" && highest_severity != "HIGH")
                highest_severity="MEDIUM"
            else if (severity == "LOW" && highest_severity == "NONE")
                highest_severity="LOW"

            account_alerts++

            print "ALERT: Multiple accounts targeted!"
            print "Severity:", severity
            print "Source IP:", ip
            print "Unique accounts targeted:", account_count[ip]
            print "Accounts:", account_list[ip]
            print "---------------------------------------"
        }
    }

    unique_account_total=0
    unique_ip_total=0

    for (user in unique_users)
        unique_account_total++

    for (ip in source_ips)
        unique_ip_total++

    print ""
    print "SOURCE IP ANALYSIS"
    print "======================================="

    for (ip in ip_attempts) {
        percentage=0

        if (total_attempts > 0)
            percentage=(ip_attempts[ip] / total_attempts) * 100

        printf "Source IP: %s | Attempts: %d | Share: %.1f%%\n", ip, ip_attempts[ip], percentage
    }

    print "---------------------------------------"

    if (top_ip != "") {
        percentage=(top_attempts / total_attempts) * 100

        print "TOP OFFENDING IP:", top_ip
        print "Failed attempts:", top_attempts
        printf "Percentage of total attempts: %.1f%%\n", percentage
    } else {
        print "No source IPs recorded."
    }

    print ""
    print "SECURITY REPORT SUMMARY"
    print "======================================="
    print "Total failed SSH attempts:", total_attempts
    print "Unique accounts targeted:", unique_account_total
    print "Unique source IPs:", unique_ip_total
    print "Repeated-login alerts:", repeated_alerts
    print "Multiple-account alerts:", account_alerts
    print "Highest severity:", highest_severity

    print ""

    if (highest_severity == "HIGH") {
        print "Overall assessment: HIGH RISK"
        exit_code=3
    }
    else if (highest_severity == "MEDIUM") {
        print "Overall assessment: SUSPICIOUS ACTIVITY"
        exit_code=2
    }
    else if (highest_severity == "LOW") {
        print "Overall assessment: LOW-LEVEL ALERTS"
        exit_code=1
    }
    else {
        print "Overall assessment: NO ALERTS DETECTED"
        exit_code=0
    }

    print "======================================="

    # Return severity as the process exit code
    exit exit_code
}
' "$LOGFILE" | tee "$REPORT_FILE"

# Capture the pipeline status immediately
SCRIPT_STATUS=$?

if [[ $SCRIPT_STATUS -eq 4 ]]; then
    echo "ERROR: Report generation failed."
    exit 4
elif [[ $SCRIPT_STATUS -ne 0 && $SCRIPT_STATUS -ne 1 && $SCRIPT_STATUS -ne 2 && $SCRIPT_STATUS -ne 3 ]]; then
    echo "ERROR: Report could not be written."
    exit 4
fi

echo ""
echo "Report saved to: $REPORT_FILE"
echo "Script exit code: $SCRIPT_STATUS"

exit "$SCRIPT_STATUS"
