import argparse
import json
import hashlib
from collections import defaultdict

# === Confidence coefficient mapper ===
def map_confidence(conf):
    return {
        "0": 0.0,
        "1": 0.5,
        "2": 0.8,
        "3": 1.0
    }.get(str(conf), 0.0)

# === Riskcode to severity ===
def map_severity(riskcode):
    risk_map = {
        "3": 5,  # CRITICAL
        "2": 3,  # HIGH
        "1": 2,  # MEDIUM
        "0": 1   # LOW
    }
    return risk_map.get(str(riskcode), 0)

def dedupe_zap(input_path, output_path, summary_path=None, details_path=None, relaxed=False):
    with open(input_path, 'r') as f:
        data = json.load(f)

    deduped_data = {"site": []}
    summary = defaultdict(lambda: {
        "count": 0, "risk": "", "confidence": "", "total_score": 0.0
    })

    for site in data.get("site", []):
        new_site = {"alerts": []}
        seen_keys = set()

        for alert in site.get("alerts", []):
            riskcode = alert.get("riskcode", "0")
            confidence = alert.get("confidence", "0")
            sev = map_severity(riskcode)
            coef = map_confidence(confidence)

            for instance in alert.get("instances", []):
                evidence = instance.get("evidence", "")
                evidence_hash = hashlib.md5(evidence.encode()).hexdigest() if relaxed else ""
                key = (
                    alert["alert"],
                    instance.get("uri", ""),
                    instance.get("method", ""),
                    instance.get("param", ""),
                    evidence_hash
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                vuln_score = sev * coef

                new_site["alerts"].append({
                    "alert": alert["alert"],
                    "riskdesc": alert.get("riskdesc", ""),
                    "confidence": confidence,
                    "uri": instance.get("uri", ""),
                    "method": instance.get("method", ""),
                    "param": instance.get("param", ""),
                    "evidence": evidence,
                    "score": round(vuln_score, 2)
                })

                summary[alert["alert"]]["count"] += 1
                summary[alert["alert"]]["risk"] = alert.get("riskdesc", "")
                summary[alert["alert"]]["confidence"] = confidence
                summary[alert["alert"]]["total_score"] += vuln_score

        deduped_data["site"].append(new_site)

    with open(output_path, 'w') as f:
        json.dump(deduped_data, f, indent=2)
    print(f"✅ Deduplicated report saved to: {output_path}")

    totalScore = 0

    if summary_path:
        with open(summary_path, 'w') as f:
            f.write("| Alert | Count | Risk | Confidence | Total Score |\n")
            f.write("|-------|-------|------|------------|-------------|\n")
            for alert, stats in summary.items():
                f.write(f"| {alert} | {stats['count']} | {stats['risk']} | {stats['confidence']} | {round(stats['total_score'], 2)} |\n")
        print(f"📊 Summary saved to: {summary_path}")

    if details_path:
        grouped_alerts = defaultdict(lambda: {
            "risk": "", 
            "confidence": "", 
            "uris": dict()  # Use dict to deduplicate URIs and track max score
        })

        for site in deduped_data["site"]:
            for alert in site["alerts"]:
                key = alert["alert"]
                uri = alert["uri"]
                score = alert["score"]

                grouped = grouped_alerts[key]
                grouped["risk"] = alert["riskdesc"]
                grouped["confidence"] = alert["confidence"]

                if uri not in grouped["uris"] or score > grouped["uris"][uri]:
                    grouped["uris"][uri] = score

        grand_total_score = 0.0

        with open(details_path, 'w') as f:
            for alert_name, info in grouped_alerts.items():
                total_score = sum(info["uris"].values())
                grand_total_score += total_score
                f.write(f"## {alert_name}\n")
                f.write(f"- **Risk:** {info['risk']}\n")
                f.write(f"- **Confidence:** {info['confidence']}\n")
                f.write(f"- **Total Score:** {round(total_score, 2)}\n")
                f.write(f"- **Affected URIs:**\n")
                for uri, score in sorted(info["uris"].items()):
                    f.write(f"  - {uri} (Score: {round(score, 2)})\n")
                f.write("\n---\n\n")

            # Write grand total at the end
            f.write(f"## 🧮 Overall Total Risk Score: {round(grand_total_score, 2)}\n")
            totalScore = {round(grand_total_score, 2)}

    print(f"📄 Grouped URI report with grand total saved to: {details_path}")

    if (totalScore > 10):
        print("❌ Weighted risk score exceeds threshold.")
    else:
        print("✅ All risk checks passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deduplicate OWASP ZAP JSON report and compute risk scores")
    parser.add_argument("input", help="Path to input ZAP JSON file")
    parser.add_argument("--output", default="zap-deduped.json", help="Output JSON path")
    parser.add_argument("--summary", help="Optional summary markdown output path")
    parser.add_argument("--details", help="Optional detailed grouped markdown output path")
    parser.add_argument("--relaxed", action="store_true", help="Enable relaxed deduplication using evidence hash")

    args = parser.parse_args()
    dedupe_zap(args.input, args.output, args.summary, args.details, args.relaxed)
